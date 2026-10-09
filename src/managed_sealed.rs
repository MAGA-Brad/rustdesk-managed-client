//! Sealed transport for managed RDS API calls.
//!
//! Each call is encrypted end to end to RDS's own X25519 key, embedded at build time, so whatever
//! terminates TLS on the way (Cloudflare, or a network that inspects HTTPS) sees only opaque bytes:
//! it cannot read the call or its credential, alter or replay it, or forge RDS's answer. Wire
//! format: see RDS `app/sealed.py`.
//!
//! - Normal networks: public-roots TLS with the edge client certificate, sealed on top.
//! - Networks whose TLS certificate is rejected (an interceptor): the sealed endpoint - and only
//!   it - is retried over a connection that accepts the interceptor's certificate, because the
//!   envelope rather than TLS protects it there. RDS decides per device and network whether to
//!   serve such calls, and alerts Brad.
//! - A call that can be sealed is never sent without the envelope. If the sealed endpoint refuses
//!   it (404/405, or a 400/503), the caller sees that refusal as a failed call and retries later:
//!   anything that can answer for the RDS host - the CDN included - could otherwise send that
//!   answer just to get the call in plaintext.
//!
//! `send_sealed()` is a drop-in for `RequestBuilder::send()`: transport failures stay real
//! `reqwest::Error`s, while an RDS answer that fails authentication becomes a 502 response, which
//! every caller already treats as a failure.

use reqwest::{RequestBuilder, Response};
use std::future::Future;

pub trait SendSealed {
    fn send_sealed(self) -> impl Future<Output = reqwest::Result<Response>> + Send;
    /// For a builder from an IPv4-only client: the interceptor-tolerant connection stays IPv4 too.
    fn send_sealed_ipv4(self) -> impl Future<Output = reqwest::Result<Response>> + Send;
}

#[cfg(any(windows, target_os = "android"))]
impl SendSealed for RequestBuilder {
    fn send_sealed(self) -> impl Future<Output = reqwest::Result<Response>> + Send {
        imp::send(self, false)
    }

    fn send_sealed_ipv4(self) -> impl Future<Output = reqwest::Result<Response>> + Send {
        imp::send(self, true)
    }
}

#[cfg(not(any(windows, target_os = "android")))]
impl SendSealed for RequestBuilder {
    fn send_sealed(self) -> impl Future<Output = reqwest::Result<Response>> + Send {
        self.send()
    }

    fn send_sealed_ipv4(self) -> impl Future<Output = reqwest::Result<Response>> + Send {
        self.send()
    }
}

#[cfg(any(windows, target_os = "android"))]
mod imp {
    use hbb_common::log;
    use reqwest::{header::CONTENT_TYPE, Request, RequestBuilder, Response, StatusCode, Url};
    use ring::{aead, agreement, digest, hkdf, rand};
    use rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        DigitallySignedStruct, SignatureScheme,
    };
    use serde_derive::{Deserialize, Serialize};
    use std::sync::{
        atomic::{AtomicBool, AtomicI64, Ordering},
        Arc, Mutex,
    };

    const SEALED_PATH: &str = "/v1/sealed";
    const REQ_MAGIC: &[u8; 4] = b"RDS1";
    const RESP_MAGIC: &[u8; 4] = b"RDR1";
    const HKDF_INFO: &[u8] = b"rdc-sealed-v1";
    const ZERO_NONCE: [u8; 12] = [0; 12];
    const MAX_SEALED_BODY: usize = 16 * 1024 * 1024;
    /// After a certificate rejection, how long calls go straight to the interceptor-tolerant
    /// connection before public-roots TLS is tried again.
    const INSPECTED_RECHECK_MS: i64 = 10 * 60 * 1000;

    static INSPECTED_UNTIL_MS: AtomicI64 = AtomicI64::new(0);
    static SEALED_REFUSED_LOGGED: AtomicBool = AtomicBool::new(false);
    /// What the latest handshake on the interceptor-tolerant connection presented: `Some` while
    /// it is intercepted, `None` once the genuine chain verifies again.
    static INTERCEPTOR: Mutex<Option<InterceptorInfo>> = Mutex::new(None);
    thread_local! {
        // Per thread, like http_client::managed_async_client: a pooled connection is driven by
        // the runtime that opened it.
        static INSPECTED_CLIENT: std::cell::RefCell<Option<reqwest::Client>> = const { std::cell::RefCell::new(None) };
        static INSPECTED_CLIENT_V4: std::cell::RefCell<Option<reqwest::Client>> = const { std::cell::RefCell::new(None) };
    }

    fn inspected_slot(ipv4: bool) -> &'static std::thread::LocalKey<std::cell::RefCell<Option<reqwest::Client>>> {
        if ipv4 {
            &INSPECTED_CLIENT_V4
        } else {
            &INSPECTED_CLIENT
        }
    }

    /// What the interceptor presented, reported to RDS (inside the envelope) for Brad's alert.
    #[derive(Clone, Default, Serialize)]
    struct InterceptorInfo {
        issuer: String,
        subject: String,
        /// Authority key identifier of the topmost presented certificate: stable for one
        /// inspecting CA even as it mints new leaf certificates.
        ca_key_id: String,
        leaf_sha256: String,
    }

    #[derive(Serialize)]
    struct Meta<'a> {
        m: &'a str,
        p: String,
        h: Vec<(String, String)>,
        t: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        i: Option<InterceptorInfo>,
    }

    #[derive(Deserialize)]
    struct ResponseMeta {
        s: u16,
        h: Vec<(String, String)>,
    }

    struct ResponseKey {
        key: [u8; 32],
        eph_pub: [u8; 32],
    }

    struct OkmLen(usize);
    impl hkdf::KeyType for OkmLen {
        fn len(&self) -> usize {
            self.0
        }
    }

    fn server_public_key() -> Option<[u8; 32]> {
        let encoded = option_env!("RUSTDESK_MANAGED_SEAL_PUBKEY")?.trim();
        crate::decode64(encoded).ok()?.try_into().ok()
    }

    fn now_ms() -> i64 {
        hbb_common::get_time()
    }

    /// Only calls to the directory host are sealed: the envelope is answered by that host, and
    /// calls elsewhere (the relay lease, RustDrop blobs) depend on reaching RDS directly.
    fn sealed_url_for(url: &Url) -> Option<Url> {
        if url.scheme() != "https" || url.path().starts_with(SEALED_PATH) {
            return None;
        }
        let base = Url::parse(option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE")?.trim()).ok()?;
        if url.host_str()? != base.host_str()? || url.port_or_known_default() != base.port_or_known_default() {
            return None;
        }
        url.join(SEALED_PATH).ok()
    }

    fn seal(server_pub: &[u8; 32], meta: &[u8], body: &[u8]) -> Result<(Vec<u8>, ResponseKey), ring::error::Unspecified> {
        let rng = rand::SystemRandom::new();
        let eph = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
        let eph_pub: [u8; 32] = eph
            .compute_public_key()?
            .as_ref()
            .try_into()
            .map_err(|_| ring::error::Unspecified)?;
        let mut salt = [0u8; 64];
        salt[..32].copy_from_slice(&eph_pub);
        salt[32..].copy_from_slice(server_pub);
        let mut okm = [0u8; 64];
        agreement::agree_ephemeral(
            eph,
            &agreement::UnparsedPublicKey::new(&agreement::X25519, server_pub),
            |shared| {
                hkdf::Salt::new(hkdf::HKDF_SHA256, &salt)
                    .extract(shared)
                    .expand(&[HKDF_INFO], OkmLen(64))?
                    .fill(&mut okm)
            },
        )??;

        let mut out = Vec::with_capacity(44 + 4 + meta.len() + body.len() + aead::MAX_TAG_LEN);
        out.extend_from_slice(REQ_MAGIC);
        out.extend_from_slice(&digest::digest(&digest::SHA256, server_pub).as_ref()[..8]);
        out.extend_from_slice(&eph_pub);
        let mut inner = Vec::with_capacity(4 + meta.len() + body.len() + aead::MAX_TAG_LEN);
        inner.extend_from_slice(&(meta.len() as u32).to_be_bytes());
        inner.extend_from_slice(meta);
        inner.extend_from_slice(body);
        // Each derived key encrypts exactly one message (fresh ephemeral key per call).
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &okm[..32])?)
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(ZERO_NONCE),
                aead::Aad::from(&out[..]),
                &mut inner,
            )?;
        out.extend_from_slice(&inner);
        let mut key = [0u8; 32];
        key.copy_from_slice(&okm[32..]);
        Ok((out, ResponseKey { key, eph_pub }))
    }

    fn open_response(key: &ResponseKey, blob: &[u8]) -> Result<http::Response<Vec<u8>>, &'static str> {
        if blob.len() < 4 + 4 + aead::MAX_TAG_LEN || &blob[..4] != RESP_MAGIC {
            return Err("framing");
        }
        let mut aad = [0u8; 36];
        aad[..4].copy_from_slice(RESP_MAGIC);
        aad[4..].copy_from_slice(&key.eph_pub);
        let mut buf = blob[4..].to_vec();
        let inner = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key.key).map_err(|_| "key")?,
        )
        .open_in_place(
            aead::Nonce::assume_unique_for_key(ZERO_NONCE),
            aead::Aad::from(&aad[..]),
            &mut buf,
        )
        .map_err(|_| "authentication")?;
        let meta_len = u32::from_be_bytes(inner.get(..4).ok_or("length")?.try_into().map_err(|_| "length")?) as usize;
        let meta_end = 4usize.checked_add(meta_len).filter(|end| *end <= inner.len()).ok_or("length")?;
        let meta: ResponseMeta = serde_json::from_slice(&inner[4..meta_end]).map_err(|_| "meta")?;
        let mut response = http::Response::builder().status(meta.s);
        for (name, value) in &meta.h {
            response = response.header(name.as_str(), value.as_str());
        }
        response.body(inner[meta_end..].to_vec()).map_err(|_| "response")
    }

    fn synthetic(status: StatusCode, detail: &str) -> Response {
        let body = serde_json::json!({ "detail": detail }).to_string().into_bytes();
        let mut response = http::Response::new(body);
        *response.status_mut() = status;
        response
            .headers_mut()
            .insert(CONTENT_TYPE, http::HeaderValue::from_static("application/json"));
        Response::from(response)
    }

    fn meta_bytes(request: &Request, interceptor: Option<InterceptorInfo>) -> Vec<u8> {
        let url = request.url();
        let p = match url.query() {
            Some(query) => format!("{}?{}", url.path(), query),
            None => url.path().to_owned(),
        };
        let h = request
            .headers()
            .iter()
            .filter_map(|(name, value)| Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned())))
            .collect();
        let meta = Meta {
            m: request.method().as_str(),
            p,
            h,
            t: now_ms() / 1000,
            i: interceptor,
        };
        serde_json::to_vec(&meta).unwrap_or_default()
    }

    pub async fn send(builder: RequestBuilder, ipv4: bool) -> reqwest::Result<Response> {
        let (client, request) = builder.build_split();
        let request = request?;
        let (Some(server_pub), Some(sealed_url)) = (server_public_key(), sealed_url_for(request.url())) else {
            return client.execute(request).await;
        };
        let body = match request.body().map(|body| body.as_bytes()) {
            None => Vec::new(),
            Some(Some(bytes)) if bytes.len() <= MAX_SEALED_BODY => bytes.to_vec(),
            Some(_) => return client.execute(request).await,
        };
        let timeout = request.timeout().copied();

        if now_ms() >= INSPECTED_UNTIL_MS.load(Ordering::Relaxed) {
            let Ok((envelope, key)) = seal(&server_pub, &meta_bytes(&request, None), &body) else {
                return Ok(synthetic(StatusCode::BAD_GATEWAY, "sealing the request failed"));
            };
            let mut outer = client
                .post(sealed_url.clone())
                .header(CONTENT_TYPE, "application/octet-stream")
                .body(envelope);
            if let Some(timeout) = timeout {
                outer = outer.timeout(timeout);
            }
            match outer.send().await {
                Ok(response) => return finish(response, &key).await,
                Err(error) if is_certificate_rejection(&error) => {
                    log::warn!(
                        "RDS TLS certificate rejected (network appears to inspect HTTPS); sealed calls continue over the intercepted connection"
                    );
                    INSPECTED_UNTIL_MS.store(now_ms() + INSPECTED_RECHECK_MS, Ordering::Relaxed);
                    // A fresh connection, so this handshake records what the network presents now
                    // rather than what a pooled connection saw earlier.
                    INSPECTED_CLIENT.with_borrow_mut(|slot| *slot = None);
                    INSPECTED_CLIENT_V4.with_borrow_mut(|slot| *slot = None);
                    if let Some(inspected) = inspected_client(ipv4) {
                        let _ = inspected.head(sealed_url.clone()).send().await;
                    }
                }
                Err(error) => return Err(error),
            }
        }

        // Inspected network: only the sealed endpoint ever goes over this connection. RDS is told
        // about the interceptor only while the latest handshake actually showed one.
        let Some(inspected) = inspected_client(ipv4) else {
            return Ok(synthetic(StatusCode::BAD_GATEWAY, "could not set up the RDS connection"));
        };
        let info = INTERCEPTOR.lock().ok().and_then(|info| info.clone());
        let Ok((envelope, key)) = seal(&server_pub, &meta_bytes(&request, info), &body) else {
            return Ok(synthetic(StatusCode::BAD_GATEWAY, "sealing the request failed"));
        };
        let mut outer = inspected
            .post(sealed_url)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(envelope);
        if let Some(timeout) = timeout {
            outer = outer.timeout(timeout);
        }
        let response = outer.send().await?;
        finish(response, &key).await
    }

    /// Anything but 200 from the sealed endpoint is returned as it is - a failed call - and never
    /// answered by resending the call without the envelope (see the module docs).
    async fn finish(response: Response, key: &ResponseKey) -> reqwest::Result<Response> {
        let status = response.status();
        if status != StatusCode::OK {
            if !SEALED_REFUSED_LOGGED.swap(true, Ordering::Relaxed) {
                log::warn!("the sealed RDS endpoint refused a call ({status}); the call is not sent without the envelope");
            }
            return Ok(response);
        }
        let bytes = response.bytes().await?;
        match open_response(key, &bytes) {
            Ok(inner) => Ok(Response::from(inner)),
            Err(reason) => {
                log::error!("sealed RDS response rejected ({reason}): not from RDS or altered in transit");
                Ok(synthetic(StatusCode::BAD_GATEWAY, "RDS response failed authentication"))
            }
        }
    }

    /// The TLS connector wraps the rustls error in an io::Error inside another io::Error, and
    /// io::Error::source() skips the error it wraps, so each io::Error is unwrapped explicitly.
    fn is_certificate_rejection(error: &reqwest::Error) -> bool {
        let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
        while let Some(err) = current {
            if let Some(tls) = err.downcast_ref::<rustls::Error>() {
                return matches!(tls, rustls::Error::InvalidCertificate(_));
            }
            current = match err.downcast_ref::<std::io::Error>().and_then(|io| io.get_ref()) {
                Some(inner) => Some(inner),
                None => err.source(),
            };
        }
        // Backstop for a wrapper that hides the rustls error entirely.
        format!("{error:?}").contains("InvalidCertificate(")
    }

    fn inspected_client(ipv4: bool) -> Option<reqwest::Client> {
        let slot = inspected_slot(ipv4);
        if let Some(client) = slot.with_borrow(|client| client.clone()) {
            return Some(client);
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let genuine = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .unwrap_or_else(|_| unreachable!("the bundled public roots are valid"));
        let config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap_or_else(|_| unreachable!("ring supports the default protocol versions"))
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InterceptorCapture { provider, genuine }))
            .with_no_client_auth();
        let client = match crate::hbbs_http::create_inspected_network_client_async(config, ipv4) {
            Ok(client) => client,
            Err(error) => {
                log::error!("could not set up the connection for an inspecting network: {error}");
                return None;
            }
        };
        slot.with_borrow_mut(|slot| *slot = Some(client.clone()));
        Some(client)
    }

    /// Accepts whatever certificate the interceptor presents (recording it) while still checking
    /// that the peer holds its key. Used only for sealed calls, which TLS does not protect. A
    /// chain that verifies against the public roots means the network no longer intercepts, so
    /// public-roots TLS is used again from the next call.
    #[derive(Debug)]
    struct InterceptorCapture {
        provider: Arc<rustls::crypto::CryptoProvider>,
        genuine: Arc<rustls::client::WebPkiServerVerifier>,
    }

    impl ServerCertVerifier for InterceptorCapture {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            if self
                .genuine
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .is_ok()
            {
                if let Ok(mut slot) = INTERCEPTOR.lock() {
                    *slot = None;
                }
                INSPECTED_UNTIL_MS.store(0, Ordering::Relaxed);
                return Ok(ServerCertVerified::assertion());
            }
            let top = intermediates.last().unwrap_or(end_entity);
            let mut info = InterceptorInfo {
                leaf_sha256: hex::encode(digest::digest(&digest::SHA256, end_entity.as_ref())),
                ..Default::default()
            };
            if let Ok((_, leaf)) = x509_parser::parse_x509_certificate(end_entity.as_ref()) {
                info.subject = leaf.subject().to_string();
            }
            if let Ok((_, cert)) = x509_parser::parse_x509_certificate(top.as_ref()) {
                info.issuer = cert.issuer().to_string();
                info.ca_key_id = cert
                    .extensions()
                    .iter()
                    .find_map(|extension| match extension.parsed_extension() {
                        x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) => {
                            aki.key_identifier.as_ref().map(|id| hex::encode(id.0))
                        }
                        _ => None,
                    })
                    .unwrap_or_else(|| hex::encode(digest::digest(&digest::SHA256, top.as_ref())));
            }
            if let Ok(mut slot) = INTERCEPTOR.lock() {
                *slot = Some(info);
            }
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider.signature_verification_algorithms.supported_schemes()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn sealed_url_only_for_directory_host() {
            let Some(base) = option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE") else { return };
            let base = Url::parse(base.trim()).unwrap();
            let inner = base.join("/v1/device/heartbeat?x=1").unwrap();
            assert_eq!(sealed_url_for(&inner).unwrap().path(), SEALED_PATH);
            assert!(sealed_url_for(&Url::parse("https://example.com/v1/device/heartbeat").unwrap()).is_none());
            assert!(sealed_url_for(&base.join(SEALED_PATH).unwrap()).is_none());
        }
    }
}
