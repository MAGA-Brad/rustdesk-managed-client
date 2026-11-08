//! Managed builds: how an initiated connection was made (route, connect time) and how it felt
//! (round-trip delay), reported to RDS as connection events so the relay fallback delay - and
//! whether direct connections are worth enabling - can be decided from real data. Sent through
//! the service, which holds the RDS credential.
use hbb_common::{log, rendezvous_proto::NatType, ResultType};
use serde_json::json;
use std::time::Instant;

pub struct ConnectionReport {
    connection_id: String,
    peer_id: String,
    session_type: &'static str,
    route: &'static str,
    connect_ms: u64,
    relay_delay_ms: u64,
    direct_outcome: Option<(&'static str, String)>,
    started: Instant,
    delay_sum: u64,
    delay_count: u64,
    delay_max: u32,
    established: bool,
}

/// RDS's direct_result (success, failed, not_attempted) and why, after a hole punch: how the race
/// of direct transports (TCP/UDP/IPv6 punch, WebRTC) ended before any relay took over.
pub fn direct_outcome<T>(
    conn: &ResultType<T>,
    direct: bool,
    forced_relay: bool,
    punch_type: &str,
    connect_timeout_ms: u64,
    my_nat_type: i32,
    peer_nat_type: NatType,
) -> (&'static str, String) {
    if forced_relay {
        return ("not_attempted", "forced_relay".to_owned());
    }
    match conn {
        Ok(_) if direct => ("success", String::new()),
        Ok(_) => ("failed", "webrtc_turn".to_owned()),
        Err(e) if e.to_string() == "No direct transport available" => {
            ("not_attempted", "no_direct_transport".to_owned())
        }
        Err(e) => (
            "failed",
            reason(format!(
                "{punch_type} punch failed in {connect_timeout_ms} ms ({}): {e}",
                nat_types(my_nat_type, peer_nat_type)
            )),
        ),
    }
}

/// The peer answered the punch with a relay (its NAT, policy or hbbs); IPv6 and WebRTC may still
/// have raced that relay.
pub fn relay_response_outcome(
    direct: bool,
    raced: bool,
    forced_relay: bool,
    my_nat_type: i32,
    peer_nat_type: NatType,
) -> (&'static str, String) {
    let nats = nat_types(my_nat_type, peer_nat_type);
    if direct {
        ("success", String::new())
    } else if forced_relay {
        ("not_attempted", "forced_relay".to_owned())
    } else if raced {
        ("failed", reason(format!("peer chose relay, IPv6/WebRTC lost the race ({nats})")))
    } else {
        ("not_attempted", reason(format!("peer chose relay ({nats})")))
    }
}

fn nat_types(my_nat_type: i32, peer_nat_type: NatType) -> String {
    let mine = match my_nat_type {
        1 => "ASYMMETRIC",
        2 => "SYMMETRIC",
        _ => "UNKNOWN_NAT",
    };
    format!("nat {mine}/{peer_nat_type:?}")
}

/// RDS keeps at most 160 characters.
fn reason(text: String) -> String {
    text.chars().take(160).collect()
}

/// RDS's route names (security_extension ConnectionTiming.route) from what Client::start reports.
fn route(direct: bool, stream_type: &str) -> &'static str {
    if !direct {
        "relay"
    } else if stream_type.contains("IPv6") {
        "ipv6"
    } else if stream_type.contains("WebRTC") {
        "webrtc"
    } else if stream_type.contains("UDP") {
        "direct_udp"
    } else {
        "direct_tcp"
    }
}

impl ConnectionReport {
    /// None for connection types RDS doesn't track (camera, terminal, port forward) or
    /// unmanaged builds.
    pub fn new(
        session_id: u64,
        round: u32,
        peer_id: &str,
        file_transfer: bool,
        remote_desktop: bool,
        direct: bool,
        stream_type: &str,
        connect_ms: u64,
        relay_delay_ms: u64,
        direct_outcome: Option<(&'static str, String)>,
    ) -> Option<Self> {
        if option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE").is_none() {
            return None;
        }
        let session_type = if file_transfer {
            "file_transfer"
        } else if remote_desktop {
            "remote_desktop"
        } else {
            return None;
        };
        Some(Self {
            connection_id: format!("rdc-{}-{}", session_id, round),
            peer_id: peer_id.to_owned(),
            session_type,
            route: route(direct, stream_type),
            connect_ms,
            relay_delay_ms,
            direct_outcome,
            started: Instant::now(),
            delay_sum: 0,
            delay_count: 0,
            delay_max: 0,
            established: false,
        })
    }

    pub fn note_delay(&mut self, last_delay_ms: u32) {
        if last_delay_ms > 0 {
            self.delay_sum += last_delay_ms as u64;
            self.delay_count += 1;
            self.delay_max = self.delay_max.max(last_delay_ms);
        }
    }

    /// Login succeeded: the connection counts as established.
    pub fn established(&mut self) {
        if self.established {
            return;
        }
        self.established = true;
        let direct = self.route != "relay";
        let (direct_result, direct_reason) = match &self.direct_outcome {
            _ if direct => ("success", ""),
            Some((result, reason)) => (*result, reason.as_str()),
            None => ("not_attempted", ""),
        };
        let mut timing = json!({
            "route": self.route,
            "connect_ms": self.connect_ms,
            "direct_result": direct_result,
            "relay_delay_ms": self.relay_delay_ms,
        });
        if !direct_reason.is_empty() {
            timing["direct_reason"] = json!(direct_reason);
        }
        timing[if direct { "direct_ms" } else { "relay_ms" }] = json!(self.connect_ms);
        self.send("established", timing);
    }

    /// The session is over: its duration and round-trip delay.
    pub fn ended(&mut self) {
        if !self.established {
            return;
        }
        let mut timing = json!({
            "route": self.route,
            "duration_s": self.started.elapsed().as_secs(),
        });
        if self.delay_count > 0 {
            timing["avg_delay_ms"] = json!(self.delay_sum / self.delay_count);
            timing["max_delay_ms"] = json!(self.delay_max);
        }
        self.send("ended", timing);
    }

    fn send(&self, event: &str, timing: serde_json::Value) {
        let body = json!({
            "connection_id": self.connection_id,
            "event": event,
            "session_type": self.session_type,
            "direction": "initiator",
            "peer_rustdesk_id": self.peer_id,
            "timing": timing,
        })
        .to_string();
        #[cfg(windows)]
        std::thread::spawn(move || {
            if let Err(err) = crate::ipc::send_managed_connection_event(body) {
                log::debug!("managed connection report not sent: {}", err);
            }
        });
        // No service on Android: the app holds the credential and posts the event itself.
        #[cfg(any(target_os = "android", feature = "rdc_gateway"))]
        std::thread::spawn(move || {
            let result = hbb_common::tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(hbb_common::anyhow::Error::from)
                .and_then(|runtime| {
                    runtime.block_on(
                        crate::hbbs_http::directory_enrollment::post_connection_event_once(body),
                    )
                });
            if let Err(err) = result {
                log::debug!("managed connection report not sent: {}", err);
            }
        });
    }
}
