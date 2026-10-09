use hbb_common::{
    async_recursion::async_recursion,
    bail,
    config::{Config, Socks5Server},
    log::{self, info},
    proxy::{Proxy, ProxyScheme},
    tls::{
        get_cached_tls_accept_invalid_cert, get_cached_tls_type, is_plain, upsert_tls_cache,
        TlsType,
    },
    ResultType,
};
use reqwest::{blocking::Client as SyncClient, Client as AsyncClient};

macro_rules! configure_http_client {
    ($builder:expr, $tls_type:expr, $danger_accept_invalid_cert:expr, $Client: ty) => {{
        // https://github.com/rustdesk/rustdesk/issues/11569
        // https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html#method.no_proxy
        // A stalled/half-open connection (dropped packets, a dead NAT
        // mapping, momentary server unresponsiveness) otherwise hangs a
        // request forever - reqwest has no default timeout. Most callers of
        // this shared client are lightweight API calls (manifest checks,
        // heartbeats, directory status) that should complete quickly under
        // normal conditions; a caller needing longer (e.g. a large file
        // download) can still override this per-request via
        // RequestBuilder::timeout(), which takes precedence over this
        // client-level default.
        let mut builder = $builder.no_proxy().timeout(std::time::Duration::from_secs(20));

        match $tls_type {
            TlsType::Plain => {}
            TlsType::NativeTls => {
                builder = builder.use_native_tls();
                if $danger_accept_invalid_cert {
                    builder = builder.danger_accept_invalid_certs(true);
                }
            }
            TlsType::Rustls => {
                #[cfg(any(target_os = "android", target_os = "ios"))]
                match hbb_common::verifier::client_config($danger_accept_invalid_cert) {
                    Ok(client_config) => {
                        builder = builder.use_preconfigured_tls(client_config);
                    }
                    Err(e) => {
                        hbb_common::log::error!("Failed to get client config: {}", e);
                    }
                }
                #[cfg(not(any(target_os = "android", target_os = "ios")))]
                {
                    builder = builder.use_rustls_tls();
                    if $danger_accept_invalid_cert {
                        builder = builder.danger_accept_invalid_certs(true);
                    }
                }
            }
        }

        let client = if let Some(conf) = Config::get_socks() {
            let proxy_result = Proxy::from_conf(&conf, None);

            match proxy_result {
                Ok(proxy) => {
                    let proxy_setup = match &proxy.intercept {
                        ProxyScheme::Http { host, .. } => {
                            reqwest::Proxy::all(format!("http://{}", host))
                        }
                        ProxyScheme::Https { host, .. } => {
                            reqwest::Proxy::all(format!("https://{}", host))
                        }
                        ProxyScheme::Socks5 { addr, .. } => {
                            reqwest::Proxy::all(&format!("socks5://{}", addr))
                        }
                    };

                    match proxy_setup {
                        Ok(mut p) => {
                            if let Some(auth) = proxy.intercept.maybe_auth() {
                                if !auth.username().is_empty() && !auth.password().is_empty() {
                                    p = p.basic_auth(auth.username(), auth.password());
                                }
                            }
                            builder = builder.proxy(p);
                            builder.build().unwrap_or_else(|e| {
                                info!("Failed to create a proxied client: {}", e);
                                <$Client>::new()
                            })
                        }
                        Err(e) => {
                            info!("Failed to set up proxy: {}", e);
                            <$Client>::new()
                        }
                    }
                }
                Err(e) => {
                    info!("Failed to configure proxy: {}", e);
                    <$Client>::new()
                }
            }
        } else {
            builder.build().unwrap_or_else(|e| {
                info!("Failed to create a client: {}", e);
                <$Client>::new()
            })
        };

        client
    }};
}

pub fn create_http_client(tls_type: TlsType, danger_accept_invalid_cert: bool) -> SyncClient {
    let builder = SyncClient::builder();
    configure_http_client!(builder, tls_type, danger_accept_invalid_cert, SyncClient)
}

pub fn create_http_client_async(
    tls_type: TlsType,
    danger_accept_invalid_cert: bool,
) -> AsyncClient {
    let builder = AsyncClient::builder();
    configure_http_client!(builder, tls_type, danger_accept_invalid_cert, AsyncClient)
}

pub fn get_url_for_tls<'a>(url: &'a str, proxy_conf: &'a Option<Socks5Server>) -> &'a str {
    if is_plain(url) {
        if let Some(conf) = proxy_conf {
            if conf.proxy.starts_with("https://") {
                return &conf.proxy;
            }
        }
    }
    url
}

pub fn create_http_client_with_url(url: &str) -> SyncClient {
    let proxy_conf = Config::get_socks();
    let tls_url = get_url_for_tls(url, &proxy_conf);
    let tls_type = get_cached_tls_type(tls_url);
    let is_tls_type_cached = tls_type.is_some();
    let tls_type = tls_type.unwrap_or(TlsType::Rustls);
    let tls_danger_accept_invalid_cert = get_cached_tls_accept_invalid_cert(tls_url);
    create_http_client_with_url_(
        url,
        tls_url,
        tls_type,
        is_tls_type_cached,
        tls_danger_accept_invalid_cert,
        tls_danger_accept_invalid_cert,
    )
}

pub fn create_http_client_with_url_strict(url: &str) -> ResultType<SyncClient> {
    let parsed_url = url::Url::parse(url)?;
    if parsed_url.scheme() != "https" {
        bail!("Strict HTTP client requires HTTPS: {}", url);
    }
    #[cfg(any(windows, target_os = "android"))]
    if option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE").is_some() {
        let builder =
            SyncClient::builder().use_preconfigured_tls(crate::managed_edge_cert::rustls_config()?);
        return Ok(configure_http_client!(builder, TlsType::Plain, false, SyncClient));
    }
    let proxy_conf = Config::get_socks();
    let tls_url = get_url_for_tls(url, &proxy_conf);
    let cached_tls_type = get_cached_tls_type(tls_url);
    let cached_danger_accept_invalid_cert = get_cached_tls_accept_invalid_cert(tls_url);
    let can_reuse_cached_probe =
        cached_tls_type.is_some() && cached_danger_accept_invalid_cert == Some(false);
    let tls_type = if can_reuse_cached_probe {
        cached_tls_type.unwrap_or(TlsType::Rustls)
    } else {
        TlsType::Rustls
    };
    Ok(create_http_client_with_url_(
        url,
        tls_url,
        tls_type,
        can_reuse_cached_probe,
        Some(false),
        Some(false),
    ))
}

fn create_http_client_with_url_(
    url: &str,
    tls_url: &str,
    tls_type: TlsType,
    is_tls_type_cached: bool,
    danger_accept_invalid_cert: Option<bool>,
    original_danger_accept_invalid_cert: Option<bool>,
) -> SyncClient {
    let danger_accept_invalid_cert = forbid_invalid_cert(url, danger_accept_invalid_cert);
    let mut client = create_http_client(tls_type, danger_accept_invalid_cert.unwrap_or(false));
    if is_tls_type_cached && original_danger_accept_invalid_cert.is_some() {
        return client;
    }
    if let Err(e) = client.head(url).send() {
        if e.is_request() {
            match (tls_type, is_tls_type_cached, danger_accept_invalid_cert) {
                (TlsType::Rustls, _, None) => {
                    log::warn!(
                        "Failed to connect to server {} with rustls-tls: {:?}, trying accept invalid cert",
                        tls_url,
                        e
                    );
                    client = create_http_client_with_url_(
                        url,
                        tls_url,
                        tls_type,
                        is_tls_type_cached,
                        Some(true),
                        original_danger_accept_invalid_cert,
                    );
                }
                (TlsType::Rustls, false, Some(_)) => {
                    log::warn!(
                        "Failed to connect to server {} with rustls-tls: {:?}, trying native-tls",
                        tls_url,
                        e
                    );
                    client = create_http_client_with_url_(
                        url,
                        tls_url,
                        TlsType::NativeTls,
                        is_tls_type_cached,
                        original_danger_accept_invalid_cert,
                        original_danger_accept_invalid_cert,
                    );
                }
                (TlsType::NativeTls, _, None) => {
                    log::warn!(
                        "Failed to connect to server {} with native-tls: {:?}, trying accept invalid cert",
                        tls_url,
                        e
                    );
                    client = create_http_client_with_url_(
                        url,
                        tls_url,
                        tls_type,
                        is_tls_type_cached,
                        Some(true),
                        original_danger_accept_invalid_cert,
                    );
                }
                _ => {
                    log::error!(
                        "Failed to connect to server {} with {:?}, err: {:?}.",
                        tls_url,
                        tls_type,
                        e
                    );
                }
            }
        } else {
            log::warn!(
                "Failed to connect to server {} with {:?}, err: {}.",
                tls_url,
                tls_type,
                e
            );
        }
    } else {
        log::info!(
            "Successfully connected to server {} with {:?}",
            tls_url,
            tls_type
        );
        upsert_tls_cache(
            tls_url,
            tls_type,
            danger_accept_invalid_cert.unwrap_or(false),
        );
    }
    client
}

/// A reused client per thread, so the RDS calls each worker makes every few seconds share a
/// kept-alive connection instead of paying a fresh TLS handshake (~6-7 KB, more than most calls'
/// own data) each time. Per thread rather than per process: a pooled connection is driven by the
/// runtime that opened it, and the service, RustDrop and chat workers each run their own.
/// Rebuilt when what it was built from changes: the edge client certificate or the proxy.
#[cfg(any(windows, target_os = "android"))]
fn managed_async_client() -> ResultType<AsyncClient> {
    type Key = (Option<std::time::SystemTime>, Option<(String, String)>);
    thread_local! {
        static CACHED: std::cell::RefCell<Option<(Key, AsyncClient)>> = const { std::cell::RefCell::new(None) };
    }
    let key: Key = (
        crate::managed_edge_cert::identity_stamp(),
        Config::get_socks().map(|socks| (socks.proxy, socks.username)),
    );
    if let Some(client) = CACHED.with_borrow(|cached| {
        cached
            .as_ref()
            .filter(|(cached_key, _)| *cached_key == key)
            .map(|(_, client)| client.clone())
    }) {
        return Ok(client);
    }
    let builder =
        AsyncClient::builder().use_preconfigured_tls(crate::managed_edge_cert::rustls_config()?);
    let client = build_managed_client(builder)?;
    CACHED.with_borrow_mut(|cached| *cached = Some((key, client.clone())));
    Ok(client)
}

/// configure_http_client! for the managed clients, failing closed: on a proxy or build error that
/// macro falls back to reqwest's default client, which would silently drop the managed TLS
/// settings (public roots, edge certificate, or the interceptor handling) and the timeout.
#[cfg(any(windows, target_os = "android"))]
fn build_managed_client(builder: reqwest::ClientBuilder) -> ResultType<AsyncClient> {
    let mut builder = builder.no_proxy().timeout(std::time::Duration::from_secs(20));
    if let Some(conf) = Config::get_socks() {
        let proxy = match Proxy::from_conf(&conf, None) {
            Ok(proxy) => proxy,
            Err(e) => bail!("Failed to configure proxy: {}", e),
        };
        let mut p = match &proxy.intercept {
            ProxyScheme::Http { host, .. } => reqwest::Proxy::all(format!("http://{}", host)),
            ProxyScheme::Https { host, .. } => reqwest::Proxy::all(format!("https://{}", host)),
            ProxyScheme::Socks5 { addr, .. } => reqwest::Proxy::all(&format!("socks5://{}", addr)),
        }?;
        if let Some(auth) = proxy.intercept.maybe_auth() {
            if !auth.username().is_empty() && !auth.password().is_empty() {
                p = p.basic_auth(auth.username(), auth.password());
            }
        }
        builder = builder.proxy(p);
    }
    Ok(builder.build()?)
}

/// Upstream's TLS probing retries a failed handshake with `danger_accept_invalid_cert`. Managed
/// builds never do that for an RDS host (any name under the managed directory's domain): it is
/// exactly how an intercepting network would read the call, so the request fails instead.
pub(crate) fn forbid_invalid_cert(url: &str, danger_accept_invalid_cert: Option<bool>) -> Option<bool> {
    #[cfg(any(windows, target_os = "android"))]
    if danger_accept_invalid_cert == Some(true) && is_managed_rds_url(url) {
        log::warn!("refusing to accept an invalid certificate for {}", url);
        return Some(false);
    }
    let _ = url;
    danger_accept_invalid_cert
}

#[cfg(any(windows, target_os = "android"))]
fn is_managed_rds_url(url: &str) -> bool {
    let Some(base) = option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE") else {
        return false;
    };
    let (Ok(base), Ok(url)) = (url::Url::parse(base.trim()), url::Url::parse(url)) else {
        return false;
    };
    let (Some(base_host), Some(host)) = (base.host_str(), url.host_str()) else {
        return false;
    };
    let domain = base_host.split_once('.').map_or(base_host, |(_, rest)| rest);
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// The managed client pinned to IPv4, for the relay lease's fallback through the directory host:
/// RDS records the caller's address for the relay guard, and the relay host is IPv4-only.
#[cfg(any(windows, target_os = "android"))]
pub fn create_managed_ipv4_client_async() -> ResultType<AsyncClient> {
    let builder = AsyncClient::builder()
        .use_preconfigured_tls(crate::managed_edge_cert::rustls_config()?)
        .local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    build_managed_client(builder)
}

/// Client for the sealed RDS endpoint on a network that intercepts TLS. Accepting the
/// interceptor's certificate is safe only because everything sent over it is sealed end to end
/// (managed_sealed.rs); nothing else may use this client. `ipv4` keeps the relay-lease fallback
/// on IPv4 here as well (see create_managed_ipv4_client_async).
#[cfg(any(windows, target_os = "android"))]
pub fn create_inspected_network_client_async(tls: rustls::ClientConfig, ipv4: bool) -> ResultType<AsyncClient> {
    let mut builder = AsyncClient::builder().use_preconfigured_tls(tls);
    if ipv4 {
        builder = builder.local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    }
    build_managed_client(builder)
}

pub async fn create_http_client_async_with_url_strict(url: &str) -> ResultType<AsyncClient> {
    let parsed_url = url::Url::parse(url)?;
    if parsed_url.scheme() != "https" {
        bail!("Strict HTTP client requires HTTPS: {}", url);
    }
    #[cfg(any(windows, target_os = "android"))]
    if option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE").is_some() {
        return managed_async_client();
    }
    let proxy_conf = Config::get_socks();
    let tls_url = get_url_for_tls(url, &proxy_conf);
    let cached_tls_type = get_cached_tls_type(tls_url);
    let cached_danger_accept_invalid_cert = get_cached_tls_accept_invalid_cert(tls_url);
    let can_reuse_cached_probe =
        cached_tls_type.is_some() && cached_danger_accept_invalid_cert == Some(false);
    let tls_type = if can_reuse_cached_probe {
        cached_tls_type.unwrap_or(TlsType::Rustls)
    } else {
        TlsType::Rustls
    };
    Ok(create_http_client_async_with_url_(
        url,
        tls_url,
        tls_type,
        can_reuse_cached_probe,
        Some(false),
        Some(false),
    )
    .await)
}

#[async_recursion]
async fn create_http_client_async_with_url_(
    url: &str,
    tls_url: &str,
    tls_type: TlsType,
    is_tls_type_cached: bool,
    danger_accept_invalid_cert: Option<bool>,
    original_danger_accept_invalid_cert: Option<bool>,
) -> AsyncClient {
    let danger_accept_invalid_cert = forbid_invalid_cert(url, danger_accept_invalid_cert);
    let mut client =
        create_http_client_async(tls_type, danger_accept_invalid_cert.unwrap_or(false));
    if is_tls_type_cached && original_danger_accept_invalid_cert.is_some() {
        return client;
    }
    if let Err(e) = client.head(url).send().await {
        match (tls_type, is_tls_type_cached, danger_accept_invalid_cert) {
            (TlsType::Rustls, _, None) => {
                log::warn!(
                    "Failed to connect to server {} with rustls-tls: {:?}, trying accept invalid cert",
                    tls_url,
                    e
                );
                client = create_http_client_async_with_url_(
                    url,
                    tls_url,
                    tls_type,
                    is_tls_type_cached,
                    Some(true),
                    original_danger_accept_invalid_cert,
                )
                .await;
            }
            (TlsType::Rustls, false, Some(_)) => {
                log::warn!(
                    "Failed to connect to server {} with rustls-tls: {:?}, trying native-tls",
                    tls_url,
                    e
                );
                client = create_http_client_async_with_url_(
                    url,
                    tls_url,
                    TlsType::NativeTls,
                    is_tls_type_cached,
                    original_danger_accept_invalid_cert,
                    original_danger_accept_invalid_cert,
                )
                .await;
            }
            (TlsType::NativeTls, _, None) => {
                log::warn!(
                    "Failed to connect to server {} with native-tls: {:?}, trying accept invalid cert",
                    tls_url,
                    e
                );
                client = create_http_client_async_with_url_(
                    url,
                    tls_url,
                    tls_type,
                    is_tls_type_cached,
                    Some(true),
                    original_danger_accept_invalid_cert,
                )
                .await;
            }
            _ => {
                log::error!(
                    "Failed to connect to server {} with {:?}, err: {:?}.",
                    tls_url,
                    tls_type,
                    e
                );
            }
        }
    } else {
        log::info!(
            "Successfully connected to server {} with {:?}",
            tls_url,
            tls_type
        );
        upsert_tls_cache(
            tls_url,
            tls_type,
            danger_accept_invalid_cert.unwrap_or(false),
        );
    }
    client
}
