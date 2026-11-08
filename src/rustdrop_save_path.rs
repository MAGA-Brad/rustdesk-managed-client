// Filesystem safety for RustDrop's downloaded files. Ports the retired
// Electron client's save-path.js checklist one-to-one (rustdrop_architecture
// doc, section 07, hardening checklist items 1/2/4/5 - item 3, the size
// cap, is enforced server-side already).

use std::collections::HashSet;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

static RESERVED_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        "CONIN$", "CONOUT$", "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
    ]
    .into_iter()
    .collect()
});

/// Direction marks and overrides: they make "invoice\u{202E}fdp.exe" display as "invoiceexe.pdf".
const BIDI_CONTROLS: [char; 12] = [
    '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}',
    '\u{2067}', '\u{2068}', '\u{2069}', '\u{061C}',
];

/// A sender's file name as Windows will save and show it (audit RDC-RUSTDROP#9): characters Windows
/// refuses, or reads as a stream name (`:`), become `_`; direction controls are dropped; trailing dots
/// and spaces, which Windows strips, are trimmed. Separators are left for assert_safe_filename.
pub fn sanitize_filename(filename: &str) -> String {
    let cleaned: String = filename
        .chars()
        .filter(|c| !BIDI_CONTROLS.contains(c))
        .map(|c| {
            if matches!(c, ':' | '<' | '>' | '"' | '|' | '?' | '*') || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    match cleaned.trim_end_matches(['.', ' ']) {
        "" => "download".to_string(),
        trimmed => trimmed.to_string(),
    }
}

const PART_MARKER: &str = ".rustdrop-part-";
const STALE_PART_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const FINISH_ATTEMPTS: u32 = 100;

#[derive(Debug)]
pub struct UnsafeFilename(pub String);

impl std::fmt::Display for UnsafeFilename {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsafe filename: {}", self.0)
    }
}
impl std::error::Error for UnsafeFilename {}

/// Checklist items 1+2: rejects anything that isn't a plain, single-segment
/// filename - no path separators (either slash direction), not `.` or `..`, no
/// drive-letter prefix, and no Windows reserved device name (checked
/// against the name before its extension, matching how Windows itself
/// treats CON.txt as the reserved device, not a real file). A sender lying
/// about its own filename this badly is the exact hostile case this
/// exists for, so this errors rather than silently coercing.
pub fn assert_safe_filename(filename: &str) -> Result<(), UnsafeFilename> {
    if filename.is_empty() {
        return Err(UnsafeFilename("empty filename".into()));
    }
    if filename.contains('/') || filename.contains('\\') {
        return Err(UnsafeFilename(
            "filename must not contain a path separator".into(),
        ));
    }
    if filename == "." || filename == ".." {
        return Err(UnsafeFilename("filename must not be '.' or '..'".into()));
    }
    let looks_like_drive_prefix = filename.len() >= 2
        && filename.as_bytes()[0].is_ascii_alphabetic()
        && filename.as_bytes()[1] == b':';
    if looks_like_drive_prefix {
        return Err(UnsafeFilename(
            "filename must not look like an absolute path".into(),
        ));
    }
    let trimmed = filename.trim_end_matches(['.', ' ']);
    let base = trimmed
        .split('.')
        .next()
        .unwrap_or(trimmed)
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    if RESERVED_NAMES.contains(base.as_str()) {
        return Err(UnsafeFilename(format!(
            "'{filename}' is a reserved Windows device name"
        )));
    }
    Ok(())
}

/// Checklist item 5: never silently overwrite - "file.ext" colliding with
/// an existing file becomes "file (1).ext", "file (2).ext", etc.
pub fn unique_destination(dir: &Path, filename: &str) -> PathBuf {
    let candidate = dir.join(filename);
    if !candidate.exists() {
        return candidate;
    }
    let path_buf = PathBuf::from(filename);
    let ext = path_buf.extension().and_then(|e| e.to_str());
    let stem = path_buf
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(filename);
    let mut n = 1u32;
    loop {
        let candidate_name = match ext {
            Some(ext) => format!("{stem} ({n}).{ext}"),
            None => format!("{stem} ({n})"),
        };
        let candidate = dir.join(&candidate_name);
        if !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

/// A temp-file handle for checklist item 4: writes go to a temp name in the
/// *same* directory as the real destination (same-directory rename is
/// atomic on NTFS - a cancelled or failed transfer can never leave a
/// corrupt file sitting at the real name). Call `finish()` once all bytes
/// are written, or drop it without finishing to leave the temp file behind
/// for `abort()`/manual cleanup - dropping is not itself a cleanup hook,
/// so callers on an error path should call `abort()` explicitly.
pub struct AtomicFileWriter {
    file: File,
    temp_path: PathBuf,
    final_path: PathBuf,
    filename: String,
}

impl AtomicFileWriter {
    pub fn create(dir: &Path, filename: &str) -> io::Result<Self> {
        let filename = sanitize_filename(filename);
        assert_safe_filename(&filename)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        fs::create_dir_all(dir)?;
        remove_stale_parts(dir);
        let final_path = unique_destination(dir, &filename);
        // Unique per download: --rustdrop is one process, so two accepts of the same name collided
        // on a pid-named temp file (audit RDC-RUSTDROP#10).
        let temp_path = {
            let mut p = final_path.clone().into_os_string();
            p.push(format!("{PART_MARKER}{}", uuid::Uuid::new_v4()));
            PathBuf::from(p)
        };
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        Ok(AtomicFileWriter {
            file,
            temp_path,
            final_path,
            filename,
        })
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Closes the temp file and moves it into place without replacing anything: a file created under
    /// the chosen name during the download keeps it, and this one takes the next free name (audit
    /// RDC-RUSTDROP#10). The temp file is removed if this fails.
    pub fn finish(self) -> io::Result<PathBuf> {
        drop(self.file);
        let placed = place_without_replacing(&self.temp_path, &self.final_path, &self.filename);
        if placed.is_err() {
            let _ = fs::remove_file(&self.temp_path);
        }
        placed
    }

    /// Deletes the temp file after a failed/cancelled transfer, leaving no
    /// trace at either the temp or final path.
    pub fn abort(self) {
        drop(self.file);
        let _ = fs::remove_file(&self.temp_path);
    }
}

/// A hard link fails when the name is taken, where a rename would replace it.
fn place_without_replacing(temp: &Path, wanted: &Path, filename: &str) -> io::Result<PathBuf> {
    let dir = wanted.parent().unwrap_or_else(|| Path::new("."));
    let mut target = wanted.to_path_buf();
    for _ in 0..FINISH_ATTEMPTS {
        match fs::hard_link(temp, &target) {
            Ok(()) => {
                if let Err(e) = fs::remove_file(temp) {
                    hbb_common::log::warn!(
                        "rustdrop: could not remove the temp file {temp:?}: {e}"
                    );
                }
                return Ok(target);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            // No hard links on this volume (FAT, exFAT, some shares): rename, only onto a free name.
            Err(_) if !target.exists() => {
                fs::rename(temp, &target)?;
                return Ok(target);
            }
            Err(_) => {}
        }
        target = unique_destination(dir, filename);
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no free name to save the file under",
    ))
}

/// A download cut short by a crash or a closed window leaves its temp file next to the destination.
fn remove_stale_parts(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let ours = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.contains(PART_MARKER));
        let stale = ours
            && entry
                .metadata()
                .ok()
                .filter(|m| m.is_file())
                .and_then(|m| m.modified().ok())
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age > STALE_PART_AGE);
        if stale {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Marks a received file as coming from another machine (Mark-of-the-Web, zone 3 = Internet), so
/// SmartScreen and Office Protected View treat it as a download (audit RDC-RUSTDROP#8). FAT and
/// exFAT volumes have no alternate data streams to hold the mark; that is only logged.
#[cfg(windows)]
pub fn mark_from_internet(path: &Path, sender: &str) {
    let mut stream = path.as_os_str().to_os_string();
    stream.push(":Zone.Identifier");
    let contents = format!(
        "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=rustdrop://{}\r\n",
        referrer_host(sender)
    );
    if let Err(e) = fs::write(&stream, contents) {
        hbb_common::log::info!("rustdrop: could not mark {path:?} as downloaded: {e}");
    }
}

#[cfg(not(windows))]
pub fn mark_from_internet(_path: &Path, _sender: &str) {}

/// The sender's name, percent-encoded so the mark's URL stays one well-formed line.
#[cfg(windows)]
fn referrer_host(sender: &str) -> String {
    sender
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rustdrop_save_path_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rejects_path_separators() {
        assert!(assert_safe_filename("a/b").is_err());
        assert!(assert_safe_filename("a\\b").is_err());
    }

    #[test]
    fn rejects_dotdot() {
        assert!(assert_safe_filename("..").is_err());
        assert!(assert_safe_filename(".").is_err());
        assert!(assert_safe_filename("a..b").is_ok());
        assert!(assert_safe_filename("v1..2.pdf").is_ok());
    }

    #[test]
    fn sanitizes_what_windows_would_misread() {
        assert_eq!(sanitize_filename("a:b.txt"), "a_b.txt");
        assert_eq!(sanitize_filename("report.txt:hidden"), "report.txt_hidden");
        assert_eq!(sanitize_filename("<>\"|?*.log"), "______.log");
        assert_eq!(
            sanitize_filename("line\nbreak\u{7}\u{85}.txt"),
            "line_break__.txt"
        );
        assert_eq!(
            sanitize_filename("invoice\u{202E}fdp.exe"),
            "invoicefdp.exe"
        );
        assert_eq!(
            sanitize_filename("a\u{200F}b\u{2066}c\u{061C}.txt"),
            "abc.txt"
        );
        assert_eq!(sanitize_filename("notes. . "), "notes");
        assert_eq!(sanitize_filename("..."), "download");
        assert_eq!(sanitize_filename(""), "download");
        assert_eq!(sanitize_filename("photo (1).jpg"), "photo (1).jpg");
        assert_eq!(
            sanitize_filename("r\u{e9}sum\u{e9} \u{65e5}\u{672c}.pdf"),
            "r\u{e9}sum\u{e9} \u{65e5}\u{672c}.pdf"
        );
    }

    #[test]
    fn rejects_newer_and_padded_reserved_names() {
        for name in [
            "CONIN$",
            "conout$.txt",
            "COM\u{b9}.txt",
            "lpt\u{b3}",
            "nul .txt",
            "CON.",
            "aux ",
        ] {
            assert!(
                assert_safe_filename(name).is_err(),
                "{name:?} must be refused"
            );
        }
        assert!(assert_safe_filename("console.txt").is_ok());
        assert!(assert_safe_filename("COM10.txt").is_ok());
    }

    #[test]
    fn same_name_downloads_do_not_collide_or_replace() {
        let dir = temp_dir();
        let mut first = AtomicFileWriter::create(&dir, "same.txt").unwrap();
        let mut second = AtomicFileWriter::create(&dir, "same.txt").unwrap();
        assert_ne!(first.temp_path, second.temp_path);
        first.file_mut().write_all(b"one").unwrap();
        second.file_mut().write_all(b"two").unwrap();
        let first_path = first.finish().unwrap();
        let second_path = second.finish().unwrap();
        assert_ne!(first_path, second_path);
        assert_eq!(fs::read(&first_path).unwrap(), b"one");
        assert_eq!(fs::read(&second_path).unwrap(), b"two");
        assert!(second_path.to_string_lossy().ends_with("same (1).txt"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn finish_never_replaces_a_file_created_during_the_download() {
        let dir = temp_dir();
        let mut writer = AtomicFileWriter::create(&dir, "report.pdf").unwrap();
        writer.file_mut().write_all(b"received").unwrap();
        let temp_path = writer.temp_path.clone();
        fs::write(dir.join("report.pdf"), b"made meanwhile").unwrap();
        let saved = writer.finish().unwrap();
        assert!(saved.to_string_lossy().ends_with("report (1).pdf"));
        assert_eq!(fs::read(dir.join("report.pdf")).unwrap(), b"made meanwhile");
        assert_eq!(fs::read(&saved).unwrap(), b"received");
        assert!(!temp_path.exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn create_sanitizes_and_clears_stale_temp_files() {
        let dir = temp_dir();
        let stale = dir.join(format!("old.bin{PART_MARKER}1234"));
        let fresh = dir.join(format!("live.bin{PART_MARKER}5678"));
        fs::write(&stale, b"left by a crash").unwrap();
        fs::write(&fresh, b"another download").unwrap();
        let two_days_ago = std::time::SystemTime::now() - Duration::from_secs(2 * 24 * 60 * 60);
        File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(two_days_ago)
            .unwrap();
        let writer = AtomicFileWriter::create(&dir, "a:b.txt").unwrap();
        assert!(writer.final_path.to_string_lossy().ends_with("a_b.txt"));
        assert!(!stale.exists() && fresh.exists());
        writer.abort();
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(windows)]
    #[test]
    fn received_files_carry_the_mark_of_the_web() {
        let dir = temp_dir();
        let path = dir.join("setup.exe");
        fs::write(&path, b"MZ").unwrap();
        mark_from_internet(&path, "Guest's PC");
        let mut stream = path.clone().into_os_string();
        stream.push(":Zone.Identifier");
        let mark = fs::read_to_string(&stream).unwrap();
        assert_eq!(
            mark,
            "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=rustdrop://Guest%27s%20PC\r\n"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            b"MZ",
            "the file's own data is untouched"
        );
        assert_eq!(referrer_host("a\r\nb/c"), "a%0D%0Ab%2Fc");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_drive_prefix() {
        assert!(assert_safe_filename("C:evil.txt").is_err());
    }

    #[test]
    fn rejects_reserved_names_regardless_of_extension() {
        assert!(assert_safe_filename("CON").is_err());
        assert!(assert_safe_filename("con.txt").is_err());
        assert!(assert_safe_filename("LPT1.log").is_err());
    }

    #[test]
    fn accepts_normal_filenames() {
        assert!(assert_safe_filename("report.pdf").is_ok());
        assert!(assert_safe_filename("photo (1).jpg").is_ok());
        assert!(assert_safe_filename("no_extension").is_ok());
    }

    #[test]
    fn unique_destination_avoids_collision() {
        let dir = temp_dir();
        let first = unique_destination(&dir, "file.txt");
        fs::write(&first, b"x").unwrap();
        let second = unique_destination(&dir, "file.txt");
        assert_ne!(first, second);
        assert!(second.to_string_lossy().contains("(1)"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_writer_produces_final_file_with_correct_content() {
        let dir = temp_dir();
        let mut writer = AtomicFileWriter::create(&dir, "hello.txt").unwrap();
        writer.file_mut().write_all(b"hello world").unwrap();
        let final_path = writer.finish().unwrap();
        assert_eq!(fs::read(&final_path).unwrap(), b"hello world");
        assert!(final_path.to_string_lossy().ends_with("hello.txt"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_writer_abort_leaves_no_temp_file() {
        let dir = temp_dir();
        let mut writer = AtomicFileWriter::create(&dir, "hello.txt").unwrap();
        writer.file_mut().write_all(b"partial").unwrap();
        let temp_path = writer.temp_path.clone();
        writer.abort();
        assert!(!temp_path.exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_writer_rejects_unsafe_filename() {
        let dir = temp_dir();
        assert!(AtomicFileWriter::create(&dir, "../evil.txt").is_err());
        fs::remove_dir_all(&dir).ok();
    }
}
