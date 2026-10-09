//! Device security posture for the device report: TPM, Secure Boot, firmware type,
//! BitLocker, patch level, antivirus, firewall and RustDesk's rules, Windows time, plus this client's own
//! identity key, passport, peer certificate and connection path. Read-only; no user data.
//!
//! The Windows facts come from one built-in PowerShell inventory (WMI/CIM and registry), run as the
//! service once per report with no window. Each section fails on its own, leaving only that field null.
use hbb_common::base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use std::{
    io::Read,
    os::windows::process::CommandExt,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const TIMEOUT: Duration = Duration::from_secs(60);

const INVENTORY: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$r = [ordered]@{}
try {
  $t = Get-CimInstance -Namespace 'root/cimv2/security/microsofttpm' -ClassName Win32_Tpm
  if ($t) {
    $m = "$($t.ManufacturerIdTxt)".Trim()
    $kind = switch -Regex ($m) { '^(INTC|AMD|QCOM)$' { 'firmware' } '^MSFT$' { 'pluton or virtual' } '^(IFX|NTC|STM|ATML|NSM|NTZ)$' { 'discrete' } '^IBM$' { 'virtual' } default { 'unknown' } }
    $r.tpm = [ordered]@{ present = $true; spec_version = ("$($t.SpecVersion)" -split ',')[0].Trim(); manufacturer = $m; manufacturer_version = "$($t.ManufacturerVersion)"; kind = $kind; enabled = [bool]$t.IsEnabled_InitialValue; activated = [bool]$t.IsActivated_InitialValue }
  } else { $r.tpm = [ordered]@{ present = $false } }
} catch { $r.tpm = [ordered]@{ present = $null; error = $_.Exception.Message } }
try { $r.secure_boot = if (Confirm-SecureBootUEFI) { 'on' } else { 'off' } } catch [System.PlatformNotSupportedException] { $r.secure_boot = 'unsupported' } catch { $r.secure_boot = $null }
$r.firmware_type = $env:firmware_type
try {
  $v = Get-CimInstance -Namespace 'root/cimv2/security/microsoftvolumeencryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$env:SystemDrive'"
  if ($v) { $r.bitlocker = [ordered]@{ protection = @('off', 'on', 'unknown')[[int]$v.ProtectionStatus]; fully_encrypted = ([int]$v.ConversionStatus -eq 1) } } else { $r.bitlocker = $null }
} catch { $r.bitlocker = $null }
try {
  $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $r.windows = [ordered]@{ display_version = $cv.DisplayVersion; edition = $cv.EditionID; build = "$($cv.CurrentBuild).$($cv.UBR)" }
} catch { $r.windows = $null }
try {
  $d = Get-MpComputerStatus
  $r.defender = [ordered]@{ antivirus_enabled = [bool]$d.AntivirusEnabled; realtime = [bool]$d.RealTimeProtectionEnabled; signature_age_days = [int]$d.AntivirusSignatureAge; mode = "$($d.AMRunningMode)" }
} catch { $r.defender = $null }
try { $r.antivirus_products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct | ForEach-Object { $_.displayName }) } catch { $r.antivirus_products = $null }
try { $p = [ordered]@{}; Get-NetFirewallProfile | ForEach-Object { $p[$_.Name] = ("$($_.Enabled)" -eq 'True') }; $r.firewall_profiles = $p } catch { $r.firewall_profiles = $null }
try {
  $fw = @(Get-NetFirewallRule -DisplayName '*RustDesk*')
  $on = @($fw | Where-Object { "$($_.Enabled)" -eq 'True' })
  $r.rustdesk_firewall_rules = [ordered]@{
    total = $fw.Count
    allow_in = @($on | Where-Object { "$($_.Direction)" -eq 'Inbound' -and "$($_.Action)" -eq 'Allow' }).Count
    allow_out = @($on | Where-Object { "$($_.Direction)" -eq 'Outbound' -and "$($_.Action)" -eq 'Allow' }).Count
    block = @($on | Where-Object { "$($_.Action)" -eq 'Block' }).Count
  }
} catch { $r.rustdesk_firewall_rules = $null }
try {
  $tp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
  $status = @(w32tm /query /status 2>$null)
  $src = ''; $last = ''
  foreach ($line in $status) {
    if ($line -match '^Source:\s*(.+)$') { $src = $Matches[1].Trim() }
    if ($line -match '^Last Successful Sync Time:\s*(.+)$') { $last = $Matches[1].Trim() }
  }
  $r.time = [ordered]@{ ntp_server = "$($tp.NtpServer)"; type = "$($tp.Type)"; source = $src; last_sync = $last; offset_seconds = $null; offset_server = $null }
  # One NTP query to the configured server(s): Windows only reports a source after its next poll (hours on laptops).
  foreach ($server in @("$($tp.NtpServer)" -split '\s+' | Where-Object { $_ } | ForEach-Object { ($_ -split ',')[0] } | Select-Object -First 2)) {
    $sample = @(w32tm /stripchart /computer:$server /samples:1 /dataonly 2>$null) -join ' '
    if ($sample -match '([+-]\d+[.,]\d+)s') {
      $r.time.offset_seconds = [math]::Round([double]::Parse(($Matches[1] -replace ',', '.'), [Globalization.CultureInfo]::InvariantCulture), 3)
      $r.time.offset_server = $server
      break
    }
  }
} catch { $r.time = $null }
try {
  $cs = Get-CimInstance -ClassName Win32_ComputerSystem
  $r.virtual_machine = [bool]("$($cs.Manufacturer) $($cs.Model)" -match 'Virtual|VMware|KVM|QEMU|Standard PC|VirtualBox|Xen|Proxmox|BHYVE')
} catch { $r.virtual_machine = $null }
$r | ConvertTo-Json -Depth 4 -Compress
"#;

fn run_inventory() -> Result<Value, String> {
    let script: Vec<u8> = INVENTORY.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    let mut child = Command::new(format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe"))
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"])
        .arg(STANDARD.encode(script))
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("inventory did not start: {e}"))?;
    let mut stdout = child.stdout.take().ok_or("no inventory output")?;
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < TIMEOUT => std::thread::sleep(Duration::from_millis(200)),
            Ok(None) => {
                let _ = child.kill();
                return Err("inventory timed out".to_owned());
            }
            Err(e) => return Err(format!("inventory: {e}")),
        }
    }
    let text = reader.join().map_err(|_| "inventory output lost".to_owned())?;
    serde_json::from_str(text.trim()).map_err(|e| format!("inventory output: {e}"))
}

/// Blocking (up to a minute): call it through `spawn_blocking`.
pub(crate) fn security_info() -> Value {
    let mut info = run_inventory().unwrap_or_else(|error| json!({ "error": error }));
    let passport = crate::managed_passport::load();
    info["identity_key_protection"] = json!(if crate::managed_passport::has_identity_key() {
        crate::managed_passport::PROTECTION
    } else {
        "none"
    });
    info["passport"] = passport.map_or(Value::Null, |p| json!({ "serial": p.serial, "exp": p.exp, "prot": p.prot }));
    info["peer_cert_expires"] = crate::managed_peer_auth::load_cert()
        .and_then(|stored| crate::managed_peer_auth::verify_cert(&stored.cert, hbb_common::get_time() / 1000).ok())
        .map_or(Value::Null, |payload| json!(payload.exp));
    let (path, since) = crate::managed_ws_fallback::current_path();
    info["connection_path"] = json!({ "path": path, "tcp_lost_seconds_ago": since });
    info
}
