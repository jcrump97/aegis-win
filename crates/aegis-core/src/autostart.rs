//! The opt-in Startup shortcut (ADR 0002 §6): `AegisWin Monitor.lnk` in the
//! user's Startup folder starts this copy with `--background` at sign-in.
//!
//! Only the app reaches this, never MCP. Enabling needs the PIN (checked by
//! the caller); turning it off does not. A shortcut that points elsewhere
//! (the stick moved, another copy) is reported, never silently replaced.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{AegisError, AegisResult, ErrorCode};
use crate::os::shortcut::{self, Shortcut};

pub const SHORTCUT_NAME: &str = "AegisWin Monitor.lnk";
pub const ARGUMENT: &str = "--background";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum AutostartState {
    /// No shortcut.
    Off,
    /// The shortcut starts this copy with `--background`.
    On,
    /// A shortcut with this name starts something else (another copy, an
    /// old drive letter) or this copy in another way.
    #[serde(rename_all = "camelCase")]
    Different { target: String, arguments: String },
    /// The shortcut exists but could not be read.
    #[serde(rename_all = "camelCase")]
    Unreadable { reason: String },
}

pub struct Autostart {
    link: PathBuf,
    exe: PathBuf,
}

fn io_err(e: std::io::Error) -> AegisError {
    AegisError::failed(format!("Startup shortcut: {e}"))
}

fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
}

impl Autostart {
    /// The shortcut in `folder` for the exe at `exe`.
    pub fn new(folder: &Path, exe: &Path) -> Self {
        Self { link: folder.join(SHORTCUT_NAME), exe: exe.to_owned() }
    }

    /// The real Startup folder and this process's exe.
    pub fn for_this_exe() -> AegisResult<Self> {
        let folder = shortcut::startup_folder().map_err(io_err)?;
        let exe = std::env::current_exe().map_err(io_err)?;
        Ok(Self::new(&folder, &exe))
    }

    pub fn link_path(&self) -> &Path {
        &self.link
    }

    /// What the shortcut would be for this copy.
    fn expected(&self) -> Shortcut {
        let working_dir = self.exe.parent().map(Path::to_owned).unwrap_or_default();
        Shortcut { target: self.exe.clone(), arguments: ARGUMENT.to_owned(), working_dir }
    }

    pub fn state(&self) -> AutostartState {
        match shortcut::read(&self.link) {
            Ok(None) => AutostartState::Off,
            Ok(Some(found)) if same_path(&found.target, &self.exe) && found.arguments.trim() == ARGUMENT => AutostartState::On,
            Ok(Some(found)) => AutostartState::Different { target: found.target.to_string_lossy().into_owned(), arguments: found.arguments },
            Err(e) => AutostartState::Unreadable { reason: e.to_string() },
        }
    }

    /// Creates the shortcut for this copy. A shortcut that points elsewhere
    /// is replaced only with `replace`, after the owner was asked.
    pub fn enable(&self, replace: bool) -> AegisResult<()> {
        match self.state() {
            AutostartState::On => return Ok(()),
            AutostartState::Off => {}
            AutostartState::Different { target, .. } if !replace => {
                return Err(AegisError::new(ErrorCode::Conflict, format!("A Startup shortcut from another AegisWin copy already exists (it starts {target}). Replace it?")));
            }
            AutostartState::Unreadable { .. } if !replace => {
                return Err(AegisError::new(ErrorCode::Conflict, "A Startup shortcut named AegisWin Monitor exists but could not be read. Replace it?"));
            }
            AutostartState::Different { .. } | AutostartState::Unreadable { .. } => {}
        }
        shortcut::write(&self.link, &self.expected(), "Starts AegisWin in the tray and resumes your monitors (AegisWin Settings).").map_err(io_err)
    }

    /// Deletes the shortcut, whatever it points to. The owner asked.
    pub fn remove(&self) -> AegisResult<()> {
        match std::fs::remove_file(&self.link) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(io_err(e)),
            _ => Ok(()),
        }
    }

    /// Deletes the shortcut only if it starts this copy: the last monitor
    /// was deleted. Another copy's shortcut is left alone. Returns true if
    /// it removed one.
    pub fn remove_if_ours(&self) -> AegisResult<bool> {
        if !self.link.exists() || self.state() != AutostartState::On {
            return Ok(false);
        }
        self.remove().map(|()| true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Autostart, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("copy-a").join("aegis-win.exe");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, b"").unwrap();
        let startup = dir.path().join("Startup");
        std::fs::create_dir_all(&startup).unwrap();
        let a = Autostart::new(&startup, &exe);
        (dir, a, startup)
    }

    #[test]
    fn enabling_writes_a_shortcut_that_starts_this_copy_in_the_background() {
        let (_dir, a, _) = setup();
        assert_eq!(a.state(), AutostartState::Off);
        a.enable(false).unwrap();
        assert_eq!(a.state(), AutostartState::On);
        let link = shortcut::read(a.link_path()).unwrap().unwrap();
        assert_eq!(link.arguments, "--background");
        assert!(same_path(&link.working_dir, a.exe.parent().unwrap()));
        a.enable(false).unwrap();
        a.remove().unwrap();
        assert_eq!(a.state(), AutostartState::Off);
        a.remove().unwrap();
    }

    #[test]
    fn another_copys_shortcut_is_reported_and_replaced_only_when_asked() {
        let (dir, a, startup) = setup();
        let other_exe = dir.path().join("copy-b").join("aegis-win.exe");
        std::fs::create_dir_all(other_exe.parent().unwrap()).unwrap();
        std::fs::write(&other_exe, b"").unwrap();
        let other = Autostart::new(&startup, &other_exe);
        other.enable(false).unwrap();

        assert!(matches!(a.state(), AutostartState::Different { ref target, .. } if target.contains("copy-b")));
        assert_eq!(a.enable(false).unwrap_err().code, ErrorCode::Conflict);
        assert!(!a.remove_if_ours().unwrap(), "deleting this copy's last monitor leaves another copy's shortcut");
        assert_eq!(other.state(), AutostartState::On);

        a.enable(true).unwrap();
        assert_eq!(a.state(), AutostartState::On);
        assert!(matches!(other.state(), AutostartState::Different { .. }));
        assert!(a.remove_if_ours().unwrap());
        assert_eq!(a.state(), AutostartState::Off);
    }

    #[test]
    fn a_broken_file_is_unreadable_not_ours() {
        let (_dir, a, _) = setup();
        std::fs::write(a.link_path(), b"not a shortcut").unwrap();
        assert!(matches!(a.state(), AutostartState::Unreadable { .. }));
        assert!(!a.remove_if_ours().unwrap());
        assert_eq!(a.enable(false).unwrap_err().code, ErrorCode::Conflict);
        a.enable(true).unwrap();
        assert_eq!(a.state(), AutostartState::On);
    }
}
