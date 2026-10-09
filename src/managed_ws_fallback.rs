//! Managed builds: reach hbbs and hbbr over WebSocket on 443 when their own ports don't get
//! through, as on networks that let only web traffic out, or block our address altogether. The
//! WebSocket goes to `/ws/id` and `/ws/relay` on the build's fallback host
//! (`RUSTDESK_MANAGED_WS_FALLBACK_HOST`), which sits behind a CDN such networks still reach. TCP
//! goes first; if it hasn't connected (and, to hbbs, finished the key exchange) within a head
//! start, WebSocket races it and the first to finish is used.
//!
//! Connections to hbbs run the signed key exchange inside the WebSocket as well, so neither the CDN
//! nor anything else terminating TLS on the way can read or forge them. Relay connections need
//! none: the session inside is end-to-end encrypted.
//!
//! Each path makes a fresh attempt every few seconds while the earlier ones are still pending, and
//! keeps the first that finishes: filtering firewalls stall some TLS handshakes at random (seen at
//! a school: the same handshake took 60 ms, 4 s, or never finished), and a new connection usually
//! goes through while the stalled one would only time out.
use hbb_common::{
    anyhow::{anyhow, Error},
    config::{use_ws, Config},
    futures::stream::{FuturesUnordered, StreamExt},
    log,
    socket_client::connect_tcp,
    tokio::{
        self,
        time::{sleep, Duration, Instant},
    },
    websocket::WsFramedStream,
    ResultType, Stream,
};
use std::{future::Future, sync::Mutex};

/// TCP's lead over WebSocket. A network that lets the ports through has finished the connect and
/// the key exchange well inside it.
const HEAD_START: Duration = Duration::from_secs(3);
/// After TCP lost to WebSocket, WebSocket leads for this long, so a blocked network doesn't cost
/// every connection the head start.
const PREFER_WS_FOR: Duration = Duration::from_secs(600);
/// Attempts per path, and how long one may stay pending before the next starts beside it.
const ATTEMPTS: usize = 3;
const STAGGER: Duration = Duration::from_secs(4);

static TCP_LOST_AT: Mutex<Option<Instant>> = Mutex::new(None);

#[derive(Clone, Copy, Debug)]
enum Kind {
    Rendezvous,
    Relay,
}

/// For the device report: "websocket" while connections lead with the 443 fallback, else "tcp", plus
/// seconds since TCP last lost. Only meaningful in the process that makes hbbs/hbbr connections.
pub fn current_path() -> (&'static str, Option<u64>) {
    match *TCP_LOST_AT.lock().unwrap() {
        Some(at) if at.elapsed() < PREFER_WS_FOR => ("websocket", Some(at.elapsed().as_secs())),
        Some(at) => ("tcp", Some(at.elapsed().as_secs())),
        None => ("tcp", None),
    }
}

/// A connection to hbbs at `host` (`domain:port`). On managed builds it comes back already
/// key-exchanged, which `secure_tcp` and `secure_tcp_required` then accept as is.
pub async fn connect_rendezvous(host: &str, key: &str, ms_timeout: u64) -> ResultType<Stream> {
    connect(host, Kind::Rendezvous, key, ms_timeout).await
}

/// A connection to hbbr at `host` (`domain:port`).
pub async fn connect_relay(host: &str, ms_timeout: u64) -> ResultType<Stream> {
    connect(host, Kind::Relay, "", ms_timeout).await
}

async fn connect(host: &str, kind: Kind, key: &str, ms_timeout: u64) -> ResultType<Stream> {
    let Some(url) = ws_url(host, kind, key) else {
        return connect_tcp(host, ms_timeout).await;
    };
    let tcp = hedged(|| async {
        let attempt = async {
            let mut stream = connect_tcp(host, ms_timeout).await?;
            if let Kind::Rendezvous = kind {
                crate::secure_tcp_required(&mut stream, key).await?;
            }
            Ok::<_, Error>(stream)
        };
        attempt.await.map_err(|e| anyhow!("TCP: {e:#}"))
    });
    let ws = hedged(|| async {
        let attempt = async {
            let ws = WsFramedStream::new(&url, None, None, ms_timeout).await?;
            let mut stream = Stream::WebSocket(ws);
            if let Kind::Rendezvous = kind {
                crate::secure_tcp_required(&mut stream, key).await?;
            }
            Ok::<_, Error>(stream)
        };
        attempt.await.map_err(|e| anyhow!("WebSocket {url}: {e:#}"))
    });
    let ws_first = TCP_LOST_AT
        .lock()
        .unwrap()
        .is_some_and(|at| at.elapsed() < PREFER_WS_FOR);
    let (result, tcp_won, tcp_tried) = if ws_first {
        let (result, winner, tcp_started) = race(ws, tcp).await;
        (result, winner == 1, tcp_started)
    } else {
        let (result, winner, _) = race(tcp, ws).await;
        (result, winner == 0, true)
    };
    let stream = result?;
    if tcp_won {
        if TCP_LOST_AT.lock().unwrap().take().is_some() {
            log::info!("{:?} {}: TCP gets through again", kind, host);
        }
    } else if tcp_tried {
        let mut lost = TCP_LOST_AT.lock().unwrap();
        if lost.is_none() {
            log::info!("{:?} {}: TCP didn't get through, using {}", kind, host, url);
        }
        *lost = Some(Instant::now());
    }
    Ok(stream)
}

/// The fallback URL for `host`, when this connection may fall back.
fn ws_url(host: &str, kind: Kind, key: &str) -> Option<String> {
    if use_ws() || Config::is_proxy() || (matches!(kind, Kind::Rendezvous) && key.is_empty()) {
        return None;
    }
    fallback_url(
        host,
        kind,
        option_env!("RUSTDESK_MANAGED_SERVER")?,
        option_env!("RUSTDESK_MANAGED_WS_FALLBACK_HOST")?,
    )
}

/// Only connections to our own server's domain fall back, so a relay a peer names elsewhere is
/// never rerouted to ours.
fn fallback_url(host: &str, kind: Kind, server: &str, ws_host: &str) -> Option<String> {
    let domain = |s: &str| {
        let s = s.trim();
        s.rsplit_once(':').map_or(s, |(d, _)| d).to_ascii_lowercase()
    };
    let ws_host = ws_host.trim();
    if ws_host.is_empty() || !hbb_common::is_domain_port_str(host) || domain(host) != domain(server) {
        return None;
    }
    let path = match kind {
        Kind::Rendezvous => "/ws/id",
        Kind::Relay => "/ws/relay",
    };
    Some(format!("wss://{ws_host}{path}"))
}

/// Runs `first`, and `second` too once `first` has failed or `HEAD_START` has passed. The first
/// success wins and the other attempt is dropped. Returns the result, which one produced it (0 or
/// 1), and whether `second` was started.
async fn race<T, A, B>(first: A, second: B) -> (ResultType<T>, usize, bool)
where
    A: Future<Output = ResultType<T>>,
    B: Future<Output = ResultType<T>>,
{
    tokio::pin!(first);
    let lead_err = tokio::select! {
        result = &mut first => match result {
            Ok(stream) => return (Ok(stream), 0, false),
            Err(err) => Some(err),
        },
        _ = sleep(HEAD_START) => None,
    };
    if let Some(first_err) = lead_err {
        return match second.await {
            Ok(stream) => (Ok(stream), 1, true),
            Err(err) => (Err(both(first_err, err)), 1, true),
        };
    }
    tokio::pin!(second);
    tokio::select! {
        result = &mut first => match result {
            Ok(stream) => (Ok(stream), 0, true),
            Err(first_err) => match second.await {
                Ok(stream) => (Ok(stream), 1, true),
                Err(err) => (Err(both(first_err, err)), 1, true),
            },
        },
        result = &mut second => match result {
            Ok(stream) => (Ok(stream), 1, true),
            Err(second_err) => match first.await {
                Ok(stream) => (Ok(stream), 0, true),
                Err(err) => (Err(both(err, second_err)), 0, true),
            },
        },
    }
}

/// Up to `ATTEMPTS` runs of `attempt`, each started `STAGGER` after the previous one, or at once when
/// every running one has failed; the first success wins and the rest are dropped. The error is the
/// last attempt's.
async fn hedged<T, F, Fut>(attempt: F) -> ResultType<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = ResultType<T>>,
{
    let mut running = FuturesUnordered::new();
    running.push(attempt());
    let mut started = 1;
    loop {
        tokio::select! {
            Some(result) = running.next() => match result {
                Ok(value) => return Ok(value),
                Err(err) if running.is_empty() => {
                    if started == ATTEMPTS {
                        return Err(err);
                    }
                    running.push(attempt());
                    started += 1;
                }
                Err(_) => {}
            },
            _ = sleep(STAGGER), if started < ATTEMPTS => {
                running.push(attempt());
                started += 1;
            }
        }
    }
}

/// Both attempts' errors, the leader's first.
fn both(first: Error, second: Error) -> Error {
    anyhow!("{first:#}; {second:#}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::bail;

    async fn ok_after(ms: u64) -> ResultType<u64> {
        sleep(Duration::from_millis(ms)).await;
        Ok(ms)
    }

    async fn err_after(ms: u64) -> ResultType<u64> {
        sleep(Duration::from_millis(ms)).await;
        bail!("failed after {ms}")
    }

    #[tokio::test(start_paused = true)]
    async fn test_race() {
        // The leader wins inside its head start; the other isn't started.
        let (r, w, started) = race(ok_after(100), ok_after(0)).await;
        assert!(r.is_ok() && w == 0 && !started);
        // A leader that fails at once starts the other straight away.
        let (r, w, started) = race(err_after(10), ok_after(100)).await;
        assert!(r.is_ok() && w == 1 && started);
        // A leader that hangs past the head start loses to the other.
        let (r, w, started) = race(ok_after(60_000), ok_after(100)).await;
        assert!(r.is_ok() && w == 1 && started);
        // Both started, the second fails: the leader still wins when it gets there.
        let (r, w, _) = race(ok_after(5_000), err_after(10)).await;
        assert!(r.is_ok() && w == 0);
        // Both fail: an error carrying both, the leader's first.
        let (r, _, _) = race(err_after(10), err_after(20)).await;
        assert_eq!(r.unwrap_err().to_string(), "failed after 10; failed after 20");
    }

    #[tokio::test(start_paused = true)]
    async fn test_hedged() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // The first attempt stalls; the second, started after STAGGER, wins.
        let n = AtomicUsize::new(0);
        let t = tokio::time::Instant::now();
        let r = hedged(|| {
            let i = n.fetch_add(1, Ordering::SeqCst);
            async move { if i == 0 { ok_after(3_600_000).await } else { ok_after(100).await.map(|_| i as u64) } }
        })
        .await;
        assert_eq!(r.unwrap(), 1);
        assert!(t.elapsed() < STAGGER + Duration::from_secs(1));
        // An attempt that fails starts the next at once; all failing gives up after ATTEMPTS.
        let n = AtomicUsize::new(0);
        let t = tokio::time::Instant::now();
        let r = hedged(|| {
            n.fetch_add(1, Ordering::SeqCst);
            err_after(10)
        })
        .await;
        assert!(r.is_err());
        assert_eq!(n.load(Ordering::SeqCst), ATTEMPTS);
        assert!(t.elapsed() < Duration::from_secs(1));
        // A quick success needs only the one attempt.
        let n = AtomicUsize::new(0);
        assert!(hedged(|| { n.fetch_add(1, Ordering::SeqCst); ok_after(50) }).await.is_ok());
        assert_eq!(n.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_fallback_url() {
        let url = |host, kind| fallback_url(host, kind, "rd.example.com:21116", "ws.example.com");
        assert_eq!(
            url("rd.example.com:21116", Kind::Rendezvous).as_deref(),
            Some("wss://ws.example.com/ws/id")
        );
        assert_eq!(
            url("RD.Example.com:21117", Kind::Relay).as_deref(),
            Some("wss://ws.example.com/ws/relay")
        );
        // Only our own server's domain, and only by name.
        assert_eq!(url("relay.example.net:21117", Kind::Relay), None);
        assert_eq!(url("192.0.2.1:21116", Kind::Rendezvous), None);
        assert_eq!(url("[2001:db8::1]:21117", Kind::Relay), None);
        assert_eq!(fallback_url("rd.example.com:21116", Kind::Rendezvous, "rd.example.com", " "), None);
    }
}
