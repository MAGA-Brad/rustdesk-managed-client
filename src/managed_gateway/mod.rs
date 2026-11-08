//! RustDWeb gateway (Linux, `--features rdc_gateway`): one enrolled RDC device in a headless process.
//! Like RDC for Android it has no --server and nothing can connect in: the directory worker
//! (enrollment, heartbeat, directory, peer and edge certificates, passport) runs in this process,
//! and its secrets are sealed to the VM's vTPM (platform::protect_machine_scope).

mod rds;
mod session;
mod web;

use crate::{
    client::{self, Client, Data, Interface, LoginConfigHandler},
    hbbs_http::directory_enrollment as directory,
};
use async_trait::async_trait;
use base::{config::keys, message_proto::*};
use hbb_common::{
    anyhow::anyhow,
    bail,
    config::{Config, LocalConfig, READ_TIMEOUT},
    flexi_logger, log,
    protobuf::Message as _,
    rendezvous_proto::ConnType,
    sha2::{Digest, Sha256},
    timeout,
    tokio::{self, sync::mpsc},
    ResultType, Stream,
};
use serde_json::{json, Value};
use std::{
    io::{BufRead, Write},
    os::unix::net::UnixListener,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

const LOG_BASENAME: &str = "rdc-gateway";
const LOG_SPEC: &str = "info,reqwest=warn,hyper_util=warn,rustls=warn,webrtc=warn,\
librustdesk::managed_passport=debug,librustdesk::managed_peer_auth=debug";
const STATUS_FILE: &str = "gateway-status.json";
const STATUS_INTERVAL: Duration = Duration::from_secs(30);

static LOGGER: Mutex<Option<flexi_logger::LoggerHandle>> = Mutex::new(None);

/// `rdc-gateway <command>`; returns the process exit code.
pub fn cli_main() -> i32 {
    if option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE").map_or(true, |v| v.trim().is_empty()) {
        eprintln!("rdc-gateway: this binary was built without the managed environment");
        return 2;
    }
    crate::common::load_custom_client();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => run(),
        Some("enroll") => enroll(&args[1..]),
        Some("status") => status(),
        Some("connect-test") => connect_test(&args[1..]),
        _ => {
            eprintln!(
                "usage: rdc-gateway run | enroll --name NAME [--email EMAIL] | status | connect-test RUSTDESK_ID"
            );
            return 2;
        }
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("rdc-gateway: {error}");
            1
        }
    }
}

fn init_log(to_stderr: bool) {
    use flexi_logger::{Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, Naming};
    let started = Logger::try_with_str(LOG_SPEC).and_then(|logger| {
        logger
            .log_to_file(FileSpec::default().directory(Config::log_path()).basename(LOG_BASENAME))
            .duplicate_to_stderr(if to_stderr { Duplicate::Info } else { Duplicate::None })
            .format(flexi_logger::opt_format)
            .rotate(
                Criterion::AgeOrSize(Age::Day, 8 * 1024 * 1024),
                Naming::Timestamps,
                Cleanup::KeepLogFiles(14),
            )
            .start()
    });
    match started {
        Ok(handle) => *LOGGER.lock().unwrap() = Some(handle),
        Err(error) => eprintln!("rdc-gateway: file log unavailable: {error}"),
    }
}

pub fn active_log_file() -> Option<PathBuf> {
    let path = Config::log_path().join(format!("{LOG_BASENAME}_rCURRENT.log"));
    path.exists().then_some(path)
}

/// hardware_info.security for debug-log uploads (the Windows security inventory's counterpart).
pub fn security_info() -> Value {
    let os = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|release| {
            release.lines().find_map(|line| {
                line.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_owned())
            })
        })
        .unwrap_or_default();
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut info = json!({
        "gateway": {
            "os": os,
            "kernel": kernel.trim(),
            // The service's sandbox hides /dev; sysfs still shows the vTPM that seals its secrets.
            "tpm": std::path::Path::new("/sys/class/tpm/tpm0").exists(),
            "secrets": "systemd-creds (host + tpm2)",
        }
    });
    info["identity_key_protection"] = json!(if crate::managed_passport::has_identity_key() {
        crate::managed_passport::PROTECTION
    } else {
        "none"
    });
    info["passport"] = crate::managed_passport::load()
        .map_or(Value::Null, |p| json!({ "serial": p.serial, "exp": p.exp, "prot": p.prot }));
    info["peer_cert_expires"] = crate::managed_peer_auth::load_cert()
        .and_then(|stored| {
            crate::managed_peer_auth::verify_cert(&stored.cert, hbb_common::get_time() / 1000).ok()
        })
        .map_or(Value::Null, |payload| json!(payload.exp));
    let (path, since) = crate::managed_ws_fallback::current_path();
    info["connection_path"] = json!({ "path": path, "tcp_lost_seconds_ago": since });
    info
}

/// One gateway per state directory: the service, `enroll` and `status --live` must not run the
/// directory worker side by side. Released when the process exits.
fn single_instance() -> ResultType<UnixListener> {
    use std::os::{linux::net::SocketAddrExt, unix::net::SocketAddr};
    let dir = Config::path("");
    let tag = hex::encode(&Sha256::digest(dir.to_string_lossy().as_bytes())[..8]);
    let addr = SocketAddr::from_abstract_name(format!("rdc-gateway-{tag}"))?;
    UnixListener::bind_addr(&addr)
        .map_err(|_| anyhow!("another rdc-gateway is running for {} (stop the service first)", dir.display()))
}

fn run() -> ResultType<()> {
    let _instance = single_instance()?;
    init_log(true);
    log::info!("RustDWeb gateway {} starting, id {}", crate::VERSION, Config::get_id());
    directory::start();
    std::thread::Builder::new().name("gateway-status".to_owned()).spawn(|| loop {
        write_status();
        std::thread::sleep(STATUS_INTERVAL);
    })?;
    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(web::serve())
}

fn status_snapshot() -> Value {
    let mut value = json!({
        "id": Config::get_id(),
        "rds_device_id": directory::current_device_id().unwrap_or_default(),
        "state": directory::state_key(),
        "text": directory::status_text(),
        "security": security_info(),
        "updated": hbb_common::get_time() / 1000,
    });
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&directory::snapshot_json()) {
        let devices = map.get("devices").and_then(Value::as_array).map_or(0, Vec::len);
        value["directory_devices"] = json!(devices);
    }
    value
}

fn write_status() {
    let path = Config::path(STATUS_FILE);
    let body = serde_json::to_vec_pretty(&status_snapshot()).unwrap_or_default();
    if let Err(error) = std::fs::write(&path, body) {
        log::warn!("gateway status not written to {}: {}", path.display(), error);
    }
}

fn status() -> ResultType<()> {
    let running = single_instance().is_err();
    let path = Config::path(STATUS_FILE);
    let mut value = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .unwrap_or_else(|| json!({ "id": Config::get_id() }));
    value["service_running"] = json!(running);
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn enroll(args: &[String]) -> ResultType<()> {
    let _instance = single_instance()?;
    init_log(false);
    let mut name = None;
    let mut email = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--name" => name = rest.next().cloned(),
            "--email" => email = rest.next().cloned(),
            other => bail!("unknown option {other}"),
        }
    }
    let Some(name) = name.filter(|n| !n.trim().is_empty()) else {
        bail!("--name is required");
    };
    Config::set_option(keys::OPTION_PRESET_DEVICE_NAME.to_owned(), name.trim().to_owned());
    let email = match email.filter(|e| !e.trim().is_empty()) {
        Some(email) => email,
        None => read_tty("Contact email: ", false)?,
    };
    Config::set_option(keys::OPTION_PRESET_DEVICE_EMAIL.to_owned(), email.trim().to_owned());
    println!("RustDesk ID: {}", Config::get_id());
    let mut password = read_tty("Enrollment password: ", true)?;
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(hbb_common::anyhow::Error::from)
        .and_then(|runtime| runtime.block_on(directory::enroll_once(&password)));
    let len = password.len();
    password.replace_range(..len, &"\0".repeat(len));
    result?;
    println!(
        "Enrollment sent. Approve \"{}\" in RDS (Client Management), then start the service.",
        name.trim()
    );
    Ok(())
}

/// Reads a line from the terminal (echo off for a secret); never from arguments or the environment.
fn read_tty(prompt: &str, secret: bool) -> ResultType<String> {
    use std::os::unix::io::AsRawFd;
    use termios::{tcsetattr, Termios, ECHO, TCSANOW};
    let tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let fd = tty.as_raw_fd();
    let original = Termios::from_fd(fd)?;
    let mut silent = original.clone();
    if secret {
        silent.c_lflag &= !ECHO;
    }
    (&tty).write_all(prompt.as_bytes())?;
    tcsetattr(fd, TCSANOW, &silent)?;
    let mut line = String::new();
    let read = std::io::BufReader::new(&tty).read_line(&mut line);
    tcsetattr(fd, TCSANOW, &original)?;
    if secret {
        (&tty).write_all(b"\n")?;
    }
    read?;
    let value = line.trim().to_owned();
    let len = line.len();
    line.replace_range(..len, &"\0".repeat(len));
    if value.is_empty() {
        bail!("nothing entered");
    }
    Ok(value)
}

/// A headless controller session: the RustDesk client's login handling (including this device's
/// RDS certificate proof), with what a UI would show going to the log.
#[derive(Clone)]
struct GatewaySession {
    lc: Arc<RwLock<LoginConfigHandler>>,
    sender: mpsc::UnboundedSender<Data>,
}

impl GatewaySession {
    fn new(peer_id: &str, display_name: String) -> (Self, mpsc::UnboundedReceiver<Data>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let lc: Arc<RwLock<LoginConfigHandler>> = Default::default();
        {
            let mut lc = lc.write().unwrap();
            lc.initialize(peer_id.to_owned(), ConnType::DEFAULT_CONN, None, false, None, None, None);
            lc.gateway_display_name = Some(display_name);
        }
        (Self { lc, sender }, receiver)
    }
}

#[async_trait]
impl Interface for GatewaySession {
    fn send(&self, data: Data) {
        let _ = self.sender.send(data);
    }

    fn msgbox(&self, msgtype: &str, title: &str, text: &str, link: &str) {
        log::info!("session {}: [{msgtype}] {title}: {text} {link}", self.get_id());
    }

    fn handle_login_error(&self, err: &str) -> bool {
        client::handle_login_error(self.lc.clone(), err, self)
    }

    fn handle_peer_info(&self, pi: PeerInfo) {
        self.lc.write().unwrap().handle_peer_info(&pi);
    }

    fn set_multiple_windows_session(&self, _sessions: Vec<WindowsSession>) {}

    // The gateway only reaches managed PCs, which skip trusted-device V2: callers pass an empty
    // (credential-less) trust session.
    async fn handle_hash(
        &self,
        pass: &str,
        hash: Hash,
        trust: &mut crate::trusted_devices::client::Session,
        peer: &mut Stream,
    ) -> bool {
        client::handle_hash(self.lc.clone(), pass, hash, self, trust, peer).await
    }

    async fn handle_login_from_ui(
        &self,
        os_username: String,
        os_password: String,
        password: String,
        remember: bool,
        trust: &mut crate::trusted_devices::client::Session,
        peer: &mut Stream,
    ) {
        if let Err(error) = client::handle_login_from_ui(
            self.lc.clone(),
            os_username,
            os_password,
            password,
            remember,
            trust,
            peer,
        )
        .await
        {
            self.on_error(&error.to_string());
        }
    }

    async fn handle_test_delay(&self, t: TestDelay, peer: &mut Stream) {
        client::handle_test_delay(t, peer).await;
    }

    fn get_lch(&self) -> Arc<RwLock<LoginConfigHandler>> {
        self.lc.clone()
    }
}

/// Phase 2 check: reach a Client through hbbs/hbbr as this device and log in with a deliberately
/// wrong password. The PC checks this device's RDS certificate before the password, so "Wrong
/// Password" proves the gateway is accepted, without asking anyone at the PC to accept.
fn connect_test(args: &[String]) -> ResultType<()> {
    let Some(peer) = args.first().cloned() else {
        bail!("connect-test needs a RustDesk ID");
    };
    init_log(true);
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async move {
        let (session, _receiver) = GatewaySession::new(&peer, "RDC Web check".to_owned());
        let key = crate::common::get_key(true).await;
        let token = LocalConfig::get_option("access_token");
        let ((mut stream, direct, _pk, _kcp, transport), _) =
            Client::start(&peer, &key, &token, ConnType::DEFAULT_CONN, session.clone()).await?;
        println!("connected to {peer}: direct={direct} transport={transport} secured={}", stream.is_secured());
        let probe = format!("rdc-gateway-check-{}", hex::encode(Sha256::digest(Config::get_id().as_bytes())));
        loop {
            let bytes = match timeout(READ_TIMEOUT, stream.next()).await {
                Err(_) => bail!("no answer from {peer}"),
                Ok(Some(Ok(bytes))) => bytes,
                Ok(Some(Err(error))) => bail!("connection error: {error}"),
                Ok(None) => bail!("{peer} closed the connection"),
            };
            let message = Message::parse_from_bytes(&bytes)?;
            match message.union {
                Some(message::Union::Hash(hash)) => {
                    session.handle_hash(&probe, hash, &mut Default::default(), &mut stream).await;
                }
                Some(message::Union::LoginResponse(response)) => match response.union {
                    Some(login_response::Union::Error(error)) => {
                        println!("{peer} answered the login: {error}");
                        return Ok(());
                    }
                    Some(login_response::Union::PeerInfo(info)) => {
                        println!("logged in to {} ({})", info.hostname, info.platform);
                        return Ok(());
                    }
                    _ => {}
                },
                Some(message::Union::TestDelay(delay)) => session.handle_test_delay(delay, &mut stream).await,
                Some(message::Union::Misc(misc)) => log::info!("misc from {peer}: {:?}", misc.union),
                _ => {}
            }
        }
    })
}
