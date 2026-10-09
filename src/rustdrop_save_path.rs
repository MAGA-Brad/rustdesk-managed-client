// Filesystem safety for RustDrop's downloaded files. Ports the retired
// Electron client's save-path.js checklist one-to-one (rustdrop_architecture
// doc, section 07, hardening checklist items 1/2/4/5 - item 3, the size
// cap, is enforced server-side already).

use std::collections::HashSet;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

static RESERVED_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ]
    .into_iter()
    .collect()
});

#[derive(Debug)]
pub struct UnsafeFilename(pub String);

impl std::fmt::Display for UnsafeFilename {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsafe filename: {}", self.0)
    }
}
impl std::error::Error for UnsafeFilename {}

/// Checklist items 1+2: rejects anything that isn't a plain, single-segment
/// filename - no path separators (either slash direction), no `..`, no
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
    if filename == "." || filename == ".." || filename.contains("..") {
        return Err(UnsafeFilename("filename must not contain '..'".into()));
    }
    let looks_like_drive_prefix = filename.len() >= 2
        && filename.as_bytes()[0].is_ascii_alphabetic()
        && filename.as_bytes()[1] == b':';
    if looks_like_drive_prefix {
        return Err(UnsafeFilename(
            "filename must not look like an absolute path".into(),
        ));
    }
    let base = filename
        .split('.')
        .next()
        .unwrap_or(filename)
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
}

impl AtomicFileWriter {
    pub fn create(dir: &Path, filename: &str) -> io::Result<Self> {
        assert_safe_filename(filename)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        fs::create_dir_all(dir)?;
        let final_path = unique_destination(dir, filename);
        let temp_path = {
            let mut p = final_path.clone().into_os_string();
            p.push(format!(".rustdrop-part-{}", std::process::id()));
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
        })
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Closes the temp file and atomically renames it into place.
    pub fn finish(self) -> io::Result<PathBuf> {
        drop(self.file);
        fs::rename(&self.temp_path, &self.final_path)?;
        Ok(self.final_path)
    }

    /// Deletes the temp file after a failed/cancelled transfer, leaving no
    /// trace at either the temp or final path.
    pub fn abort(self) {
        drop(self.file);
        let _ = fs::remove_file(&self.temp_path);
    }
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
        assert!(assert_safe_filename("a..b").is_err());
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
