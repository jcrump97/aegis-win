//! Facts about the AegisWin checkout: where it is, and whether packages or the app need rebuilding.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Release binary produced by `tauri build` (bundling is off, so this is the whole app).
pub const APP_EXE: &str = r"src-tauri\target\release\aegis-win.exe";
pub const TAURI_CLI: &str = r"node_modules\@tauri-apps\cli\tauri.js";
const NPM_MARKER: &str = r"node_modules\.package-lock.json";

/// Files and folders whose changes mean the app must be rebuilt.
const BUILD_INPUT_FILES: &[&str] = &["index.html", "package.json", "package-lock.json", "vite.config.ts"];
const BUILD_INPUT_DIRS: &[&str] = &["src", "plugins", "src-tauri"];
/// Build output and dependencies inside those folders.
const SKIP_DIRS: &[&str] = &["target", "gen", "node_modules", ".git"];

/// The checkout root is the nearest folder (starting at `start`) with package.json and the Tauri config.
pub fn find_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|d| d.join("package.json").is_file() && d.join(r"src-tauri\tauri.conf.json").is_file())
        .map(Path::to_path_buf)
}

fn mtime(p: &Path) -> Option<SystemTime> {
    fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// npm records a successful install in node_modules\.package-lock.json; reinstall when it is
/// missing, older than package-lock.json, or the Tauri CLI is absent.
pub fn needs_npm_install(root: &Path) -> bool {
    if !root.join(TAURI_CLI).is_file() {
        return true;
    }
    match (mtime(&root.join("package-lock.json")), mtime(&root.join(NPM_MARKER))) {
        (Some(lock), Some(marker)) => lock > marker,
        _ => true,
    }
}

/// Newest modification time among the build inputs.
pub fn newest_input(root: &Path) -> Option<SystemTime> {
    let mut newest = BUILD_INPUT_FILES.iter().filter_map(|f| mtime(&root.join(f))).max();
    let mut stack: Vec<PathBuf> = BUILD_INPUT_DIRS.iter().map(|d| root.join(d)).collect();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else { continue };
            if kind.is_dir() {
                if !SKIP_DIRS.iter().any(|s| entry.file_name().eq_ignore_ascii_case(s)) {
                    stack.push(entry.path());
                }
            } else if let Some(t) = entry.metadata().ok().and_then(|m| m.modified().ok()) {
                newest = newest.max(Some(t));
            }
        }
    }
    newest
}

pub fn needs_build(root: &Path) -> bool {
    match mtime(&root.join(APP_EXE)) {
        None => true,
        Some(built) => newest_input(root).is_some_and(|newest| newest > built),
    }
}

/// A running exe can't be opened for writing (ERROR_SHARING_VIOLATION), which is also why it
/// can't be rebuilt while open.
pub fn is_running(exe: &Path) -> bool {
    const ERROR_SHARING_VIOLATION: i32 = 32;
    exe.is_file()
        && fs::OpenOptions::new()
            .write(true)
            .open(exe)
            .is_err_and(|e| e.raw_os_error() == Some(ERROR_SHARING_VIOLATION))
}

/// PATH for child processes: the tools we found first, then the inherited PATH. Needed because
/// tools installed during this run aren't on the PATH this process started with, and `tauri build`
/// looks up `cargo` and `npm` by name.
pub fn child_path(tool_dirs: &[PathBuf], inherited: &[PathBuf]) -> OsString {
    let mut dirs: Vec<&PathBuf> = Vec::new();
    for d in tool_dirs.iter().chain(inherited) {
        let quoted = d.as_os_str().to_string_lossy().contains('"');
        if !quoted && !dirs.iter().any(|seen| seen.as_os_str().eq_ignore_ascii_case(d.as_os_str())) {
            dirs.push(d);
        }
    }
    std::env::join_paths(dirs).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aegis-launcher-project-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src-tauri")).unwrap();
        fs::write(dir.join("package.json"), "{}").unwrap();
        fs::write(dir.join(r"src-tauri\tauri.conf.json"), "{}").unwrap();
        dir
    }

    fn touch(path: &Path, when: SystemTime) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"x").unwrap();
        fs::File::options().write(true).open(path).unwrap().set_modified(when).unwrap();
    }

    #[test]
    fn finds_root_from_a_nested_folder() {
        let root = scratch("root");
        let nested = root.join(r"launcher\target\release");
        fs::create_dir_all(&nested).unwrap();
        assert_eq!(find_root(&nested), Some(root.clone()));
        assert_eq!(find_root(&std::env::temp_dir().join("aegis-launcher-nowhere")), None);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn npm_install_tracks_the_lockfile() {
        let root = scratch("npm");
        let t0 = SystemTime::now() - Duration::from_secs(3600);
        touch(&root.join("package-lock.json"), t0);
        assert!(needs_npm_install(&root), "no node_modules yet");
        touch(&root.join(TAURI_CLI), t0);
        touch(&root.join(NPM_MARKER), t0 + Duration::from_secs(10));
        assert!(!needs_npm_install(&root));
        touch(&root.join("package-lock.json"), t0 + Duration::from_secs(20));
        assert!(needs_npm_install(&root), "lockfile changed after the install");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn build_is_needed_only_when_a_source_is_newer_than_the_exe() {
        let root = scratch("build");
        let t0 = SystemTime::now() - Duration::from_secs(3600);
        for input in ["package.json", r"src-tauri\tauri.conf.json", r"src\ui\app.ts"] {
            touch(&root.join(input), t0);
        }
        assert!(needs_build(&root), "never built");
        touch(&root.join(APP_EXE), t0 + Duration::from_secs(10));
        // Build output and dependencies must not count as source changes.
        touch(&root.join(r"src-tauri\target\release\deps\x.rlib"), t0 + Duration::from_secs(60));
        touch(&root.join(r"src-tauri\gen\schemas\s.json"), t0 + Duration::from_secs(60));
        touch(&root.join(r"plugins\p\node_modules\m.js"), t0 + Duration::from_secs(60));
        assert!(!needs_build(&root));
        touch(&root.join(r"plugins\event-logs\index.mjs"), t0 + Duration::from_secs(20));
        assert!(needs_build(&root));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn child_path_puts_tools_first_without_duplicates() {
        let joined = child_path(
            &[PathBuf::from(r"C:\Program Files\nodejs"), PathBuf::from(r"C:\Users\u\.cargo\bin")],
            &[PathBuf::from(r"c:\program files\NODEJS"), PathBuf::from(r#"C:\bad"dir"#), PathBuf::from(r"C:\Windows")],
        );
        let dirs: Vec<PathBuf> = std::env::split_paths(&joined).collect();
        assert_eq!(
            dirs,
            [r"C:\Program Files\nodejs", r"C:\Users\u\.cargo\bin", r"C:\Windows"].map(PathBuf::from)
        );
    }

    #[test]
    fn missing_exe_is_not_running() {
        assert!(!is_running(Path::new(r"C:\definitely\not\here.exe")));
    }
}
