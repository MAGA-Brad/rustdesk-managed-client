//! Encrypted Client Hello for rustls with the `ring` provider: ECH config discovery over
//! DNS-over-HTTPS and an ECH-enabled `ClientConfig`.

pub mod dns;
pub mod hpke;

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hbb_common::log;

use ring::rand::{SecureRandom, SystemRandom};
use rustls::client::{EchConfig, EchMode, EchStatus};
use rustls::internal::msgs::codec::Codec;
use rustls::pki_types::{CertificateDer, EchConfigListBytes, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, PeerIncompatible, RootCertStore, StreamOwned};

// IP literals so the lookup needs no plaintext DNS and sends no SNI. Quad9 (9.9.9.9) is
// absent because its DoH answers HTTP/1.1 with 505; Cisco's 208.67.222.222 accepts it.
pub const DOH_RESOLVERS: [IpAddr; 3] = [
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)),
];
const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE: usize = 64 * 1024;

#[derive(Debug)]
pub enum ProbeResult {
    Accepted(String),
    /// The server refused our config; carries its retry configs as ECHConfigList bytes.
    Rejected(Option<Vec<u8>>),
    Failed(String),
}

pub fn fetch_ech_config_list(host: &str) -> Option<Vec<u8>> {
    for resolver in DOH_RESOLVERS {
        match doh_ech_config_list(resolver, host) {
            Ok(Some(list)) => return Some(list),
            Ok(None) => log::info!("DoH {resolver}: no ECH config for {host}"),
            Err(e) => log::warn!("DoH {resolver} lookup for {host} failed: {e}"),
        }
    }
    None
}

pub fn doh_ech_config_list(resolver: IpAddr, host: &str) -> io::Result<Option<Vec<u8>>> {
    let mut id = [0u8; 2];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| io::Error::other("no random bytes"))?;
    let id = u16::from_be_bytes(id);
    let query = dns::build_query(host, id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid host name"))?;

    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(root_store())
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let mut tls = connect(
        TcpStream::connect_timeout(&SocketAddr::new(resolver, 443), TIMEOUT)?,
        ServerName::from(resolver),
        config,
    )?;
    let mut request = format!(
        "POST /dns-query HTTP/1.1\r\nHost: {resolver}\r\nContent-Type: application/dns-message\r\n\
         Accept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        query.len()
    )
    .into_bytes();
    request.extend_from_slice(&query);
    tls.write_all(&request)?;

    let body = read_http_ok(&mut tls)?;
    Ok(dns::parse_ech_config_list(&body, id))
}

pub fn ech_client_config(
    ech_list: &[u8],
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<ClientConfig, rustls::Error> {
    let ech = EchConfig::new(EchConfigListBytes::from(ech_list), hpke::ALL_SUITES)?;
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_ech(EchMode::Enable(ech))?
            .with_root_certificates(root_store());
    match client_auth {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key),
        None => Ok(builder.with_no_client_auth()),
    }
}

pub fn probe(host: &str, ech_list: &[u8]) -> ProbeResult {
    match probe_trace(host, ech_list) {
        Ok(trace) => ProbeResult::Accepted(trace),
        Err(e) => match ech_retry_configs(&e) {
            Some(retry) => ProbeResult::Rejected(retry),
            None => ProbeResult::Failed(e.to_string()),
        },
    }
}

fn probe_trace(host: &str, ech_list: &[u8]) -> io::Result<String> {
    let config = ech_client_config(ech_list, None).map_err(io::Error::other)?;
    let name = ServerName::try_from(host.to_owned())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut tls = connect(connect_host(host, 443)?, name, config)?;
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    let status = tls.conn.ech_status();
    if status != EchStatus::Accepted {
        return Err(io::Error::other(format!(
            "unexpected ECH status {status:?}"
        )));
    }
    tls.write_all(
        format!("GET /cdn-cgi/trace HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )?;
    let body = read_http_ok(&mut tls)?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// `Some(retry)` when the error is the server rejecting our ECH offer.
pub fn ech_retry_configs(err: &io::Error) -> Option<Option<Vec<u8>>> {
    match err.get_ref()?.downcast_ref::<rustls::Error>()? {
        rustls::Error::PeerIncompatible(PeerIncompatible::ServerRejectedEncryptedClientHello(
            retry,
        )) => Some(retry.as_ref().map(|configs| configs.get_encoding())),
        _ => None,
    }
}

fn root_store() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

fn connect_host(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last_err = io::Error::new(io::ErrorKind::NotFound, "host has no addresses");
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, TIMEOUT) {
            Ok(sock) => return Ok(sock),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn connect(
    sock: TcpStream,
    name: ServerName<'static>,
    config: ClientConfig,
) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
    sock.set_read_timeout(Some(TIMEOUT))?;
    sock.set_write_timeout(Some(TIMEOUT))?;
    let conn = ClientConnection::new(Arc::new(config), name).map_err(io::Error::other)?;
    Ok(StreamOwned::new(conn, sock))
}

/// Reads one HTTP/1.1 response and returns the body of a 200. Stops at the end of the framed
/// body because some servers (OpenDNS) keep the connection open despite `Connection: close`.
fn read_http_ok(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let (status, body) = loop {
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // Peers that skip close_notify; truncation is still caught by the framing checks.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e),
        };
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > MAX_RESPONSE {
            return Err(invalid("HTTP response too large"));
        }
        if let Some(response) = parse_http_response(&raw, n == 0)? {
            break response;
        }
    };
    if status != 200 {
        return Err(io::Error::other(format!("HTTP status {status}")));
    }
    Ok(body)
}

/// `Ok(None)` while the response is incomplete and the peer may still send more.
fn parse_http_response(raw: &[u8], eof: bool) -> io::Result<Option<(u16, Vec<u8>)>> {
    let Some(header_end) = find(raw, b"\r\n\r\n") else {
        return if eof {
            Err(invalid("truncated HTTP header"))
        } else {
            Ok(None)
        };
    };
    let head = std::str::from_utf8(&raw[..header_end]).map_err(|_| invalid("bad HTTP header"))?;
    let body = &raw[header_end + 4..];
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| invalid("bad HTTP status line"))?;

    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(value.parse::<usize>().map_err(|_| invalid("bad length"))?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        }
    }

    let body = if chunked {
        dechunk(body)?
    } else if let Some(len) = content_length {
        body.get(..len).map(<[u8]>::to_vec)
    } else {
        eof.then(|| body.to_vec())
    };
    match body {
        Some(body) => Ok(Some((status, body))),
        None if eof => Err(invalid("truncated HTTP body")),
        None => Ok(None),
    }
}

/// `Ok(None)` until the terminating zero-size chunk has arrived.
fn dechunk(mut data: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = find(data, b"\r\n") else {
            return Ok(None);
        };
        let size = std::str::from_utf8(&data[..line_end])
            .ok()
            .and_then(|line| line.split(';').next())
            .and_then(|size| usize::from_str_radix(size.trim(), 16).ok())
            .ok_or_else(|| invalid("bad chunk size"))?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(Some(out));
        }
        let rest = size.checked_add(2).and_then(|end| data.get(end..));
        let (Some(chunk), Some(rest)) = (data.get(..size), rest) else {
            return Ok(None);
        };
        out.extend_from_slice(chunk);
        data = rest;
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

// RDC (build 38): a network filter that blocks by the server name (SNI) sees only the CDN's public
// name when the directory is reached with ECH. One config per process, checked on first use and
// hourly on a blocking thread; until a check succeeds, or whenever it says not to, RDC connects as
// it did before.

const RECHECK: Duration = Duration::from_secs(60 * 60);
const RECHECK_SOON: Duration = Duration::from_secs(2 * 60);
/// The server answered without ECH.
const OFF_NOT_OFFERED: Duration = Duration::from_secs(6 * 60 * 60);
/// ECH failed where a plain handshake works: a network that drops ECH offers.
const OFF_BLOCKED: Duration = Duration::from_secs(30 * 60);

struct State {
    list: Option<Vec<u8>>,
    generation: u64,
    next_check: Option<Instant>,
    off_until: Option<Instant>,
    checking: bool,
}

static STATE: Mutex<State> = Mutex::new(State {
    list: None,
    generation: 0,
    next_check: None,
    off_until: None,
    checking: false,
});

enum Outcome {
    Use(Vec<u8>, Duration),
    Off(Duration),
    Unknown,
}

fn directory_host() -> Option<String> {
    let base = url::Url::parse(option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE")?.trim()).ok()?;
    base.host_str().map(str::to_owned)
}

/// The directory host, the only host reached with ECH; every other connection is made as before.
pub fn is_ech_host(host: &str) -> bool {
    directory_host().as_deref() == Some(host)
}

/// The config to reach the directory with now, and a generation that changes with it.
pub async fn current() -> Option<(Vec<u8>, u64)> {
    let host = directory_host()?;
    let previous = {
        let mut state = STATE.lock().unwrap();
        let due = state.next_check.map_or(true, |at| Instant::now() >= at);
        if !due || state.checking {
            return usable(&state);
        }
        state.checking = true;
        state.list.clone()
    };
    // Recorded on the blocking thread, so a caller dropped mid-check (a select! that lost) cannot
    // leave `checking` set, and every later call skipping the check, for the process lifetime.
    let checked =
        hbb_common::tokio::task::spawn_blocking(move || record(check(&host, previous))).await;
    if checked.is_err() {
        record(Outcome::Unknown);
    }
    usable(&STATE.lock().unwrap())
}

fn record(outcome: Outcome) {
    let mut state = STATE.lock().unwrap();
    state.checking = false;
    let now = Instant::now();
    match outcome {
        Outcome::Use(list, recheck) => {
            if state.list.as_deref() != Some(list.as_slice()) {
                state.list = Some(list);
                state.generation += 1;
            }
            state.off_until = None;
            state.next_check = Some(now + recheck);
        }
        Outcome::Off(duration) => {
            state.off_until = Some(now + duration);
            state.next_check = Some(now + RECHECK.min(duration));
        }
        Outcome::Unknown => state.next_check = Some(now + RECHECK_SOON),
    }
}

/// The directory host rejected our ECH offer on a real call (its keys rotated): check on the next
/// call instead of at the next scheduled check.
pub fn recheck_soon() {
    STATE.lock().unwrap().next_check = Some(Instant::now());
}

/// For a synchronous caller: what the last check settled on.
pub fn cached() -> Option<(Vec<u8>, u64)> {
    usable(&STATE.lock().unwrap())
}

fn usable(state: &State) -> Option<(Vec<u8>, u64)> {
    if state.off_until.map_or(false, |until| Instant::now() < until) {
        return None;
    }
    state.list.clone().map(|list| (list, state.generation))
}

/// The CDN's shared ECH config when this build was made. Its keys rotate within hours, but a
/// stale config still works as a start: the server rejects it with its current configs, sent over
/// a handshake its certificate for the public name vouches for. Used only when no lookup answers.
const BUILTIN_CONFIG_B64: &str =
    "AEX+DQBB5wAgACDnl6VsFGX/NJ8i90u4vRh2UMvz9D/PFg6RGV7U0x0gVQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=";

fn builtin_config() -> Option<Vec<u8>> {
    log::info!("ECH: no lookup answered, starting from the built-in config");
    crate::decode64(BUILTIN_CONFIG_B64).ok()
}

fn check(host: &str, previous: Option<Vec<u8>>) -> Outcome {
    let Some(list) = fetch_ech_config_list(host).or(previous).or_else(builtin_config) else {
        log::info!("ECH: no config for {host} yet, connecting without it");
        return Outcome::Unknown;
    };
    match probe(host, &list) {
        ProbeResult::Accepted(trace) => {
            let sni = trace.lines().find(|line| line.starts_with("sni=")).unwrap_or("");
            log::info!("ECH: {host} accepted ({sni})");
            Outcome::Use(list, RECHECK)
        }
        ProbeResult::Rejected(Some(retry)) => {
            log::info!("ECH: {host} rotated its keys, using the ones it sent");
            Outcome::Use(retry, RECHECK_SOON)
        }
        ProbeResult::Rejected(None) => {
            log::warn!("ECH: {host} no longer offers it");
            Outcome::Off(OFF_NOT_OFFERED)
        }
        ProbeResult::Failed(e) => match probe_plain(host) {
            Ok(()) => {
                log::warn!("ECH: {host} failed ({e}) where a plain handshake works");
                Outcome::Off(OFF_BLOCKED)
            }
            Err(plain) => {
                log::info!("ECH: {host} failed ({e}), plain too ({plain}); keeping ECH");
                Outcome::Use(list, RECHECK_SOON)
            }
        },
    }
}

fn probe_plain(host: &str) -> io::Result<()> {
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(root_store())
            .with_no_client_auth();
    let name = ServerName::try_from(host.to_owned())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut tls = connect(connect_host(host, 443)?, name, config)?;
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::internal::msgs::codec::Reader;
    use rustls::internal::msgs::handshake::EchConfigPayload;

    fn fixture_list() -> Vec<u8> {
        dns::parse_ech_config_list(dns::tests::FIXTURE, dns::tests::FIXTURE_ID).unwrap()
    }

    #[test]
    fn a_recorded_check_clears_the_checking_flag() {
        STATE.lock().unwrap().checking = true;
        record(Outcome::Unknown);
        {
            let state = STATE.lock().unwrap();
            assert!(!state.checking);
            assert!(state.next_check.is_some_and(|at| at > Instant::now()));
        }
        recheck_soon();
        assert!(STATE
            .lock()
            .unwrap()
            .next_check
            .is_some_and(|at| at <= Instant::now()));
    }

    #[test]
    fn config_from_live_fixture_selects_our_suite() {
        assert!(ech_client_config(&fixture_list(), None).is_ok());
    }

    #[test]
    fn config_rejects_unsupported_lists() {
        assert!(ech_client_config(b"\x00\x01", None).is_err());
        // Same config, but advertising only AES-256-GCM.
        let mut list = fixture_list();
        // extensions(2) public_name(18) its length(1) maximum_name_length(1) suite(4)
        let suite = list.len() - 2 - 18 - 1 - 1 - 4;
        assert_eq!(&list[suite..suite + 4], &[0, 1, 0, 1]);
        list[suite + 3] = 2;
        assert!(ech_client_config(&list, None).is_err());
    }

    #[test]
    fn retry_configs_round_trip_through_rustls_codec() {
        let list = fixture_list();
        let configs = Vec::<EchConfigPayload>::read(&mut Reader::init(&list)).unwrap();
        let err = io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::PeerIncompatible(PeerIncompatible::ServerRejectedEncryptedClientHello(
                Some(configs),
            )),
        );
        assert_eq!(ech_retry_configs(&err), Some(Some(list)));

        let err = io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::PeerIncompatible(PeerIncompatible::ServerRejectedEncryptedClientHello(
                None,
            )),
        );
        assert_eq!(ech_retry_configs(&err), Some(None));
        assert_eq!(ech_retry_configs(&io::Error::other("x")), None);
    }

    #[test]
    fn http_framing() {
        let full = |raw: &[u8]| parse_http_response(raw, false).unwrap().unwrap();
        assert_eq!(
            full(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef"),
            (200, b"abc".to_vec())
        );
        assert_eq!(
            full(b"HTTP/1.1 404 Nope\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n"),
            (404, b"abcde".to_vec())
        );

        for partial in [
            &b"HTTP/1.1 200 OK\r\n"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab",
            b"HTTP/1.1 200 OK\r\n\r\nunframed",
        ] {
            assert!(parse_http_response(partial, false).unwrap().is_none());
        }
        for truncated in [
            &b"HTTP/1.1 200 OK\r\n"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
        ] {
            assert!(parse_http_response(truncated, true).is_err());
        }
        assert_eq!(
            parse_http_response(b"HTTP/1.1 200 OK\r\n\r\nunframed", true).unwrap(),
            Some((200, b"unframed".to_vec()))
        );
        assert!(parse_http_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            false
        )
        .is_err());
        assert!(parse_http_response(b"garbage\r\n\r\n", false).is_err());
    }

    struct TimesOut;

    impl Read for TimesOut {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::TimedOut.into())
        }
    }

    #[test]
    fn complete_response_does_not_wait_for_close() {
        let response = &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"[..];
        assert_eq!(read_http_ok(&mut response.chain(TimesOut)).unwrap(), b"ok");
        let partial = &b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok"[..];
        assert!(read_http_ok(&mut partial.chain(TimesOut)).is_err());
        let not_ok = &b"HTTP/1.1 505 HTTP Version Not Supported\r\n\r\n"[..];
        assert!(read_http_ok(&mut { not_ok }).is_err());
    }
}
