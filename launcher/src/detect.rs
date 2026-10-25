//! Finds the tools AegisWin needs to build and run. Nothing in this module changes the machine.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Oldest Node.js major version the build supports (CI uses 20).
pub const MIN_NODE_MAJOR: u32 = 20;
/// Visual Studio component that provides the MSVC compiler and linker.
const VC_TOOLS_COMPONENT: &str = "Microsoft.VisualStudio.Component.VC.Tools.x86.x64";

/// Well-known Windows folders and the PATH, read once from the environment.
#[derive(Clone, Debug, Default)]
pub struct Dirs {
    pub program_files: PathBuf,
    pub program_files_x86: PathBuf,
    pub local_app_data: PathBuf,
    pub cargo_bin: PathBuf,
    pub path: Vec<PathBuf>,
}

impl Dirs {
    pub fn from_env() -> Self {
        let var = |key: &str| std::env::var_os(key).map(PathBuf::from);
        let user_profile = var("USERPROFILE").unwrap_or_else(|| PathBuf::from(r"C:\Users\Default"));
        let cargo_home = var("CARGO_HOME").unwrap_or_else(|| user_profile.join(".cargo"));
        Dirs {
            program_files: var("ProgramFiles").unwrap_or_else(|| PathBuf::from(r"C:\Program Files")),
            program_files_x86: var("ProgramFiles(x86)")
                .unwrap_or_else(|| PathBuf::from(r"C:\Program Files (x86)")),
            local_app_data: var("LOCALAPPDATA").unwrap_or_else(|| user_profile.join(r"AppData\Local")),
            cargo_bin: cargo_home.join("bin"),
            path: std::env::var_os("PATH")
                .map(|p| std::env::split_paths(&p).collect())
                .unwrap_or_default(),
        }
    }
}

/// True if anything exists at `p`. Uses link metadata so winget's App Execution Alias counts.
pub fn exists(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

/// Every absolute location of `exe`: PATH entries first (the user's choice wins), then `known`
/// fallbacks for tools installed after this process started. Relative PATH entries are ignored
/// so a file planted in the current folder is never picked up.
pub fn find_all(exe: &str, known: &[PathBuf], path: &[PathBuf]) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let candidates = path.iter().filter(|d| d.is_absolute()).map(|d| d.join(exe));
    for p in candidates.chain(known.iter().cloned()) {
        if exists(&p) && !found.iter().any(|f| same_path(f, &p)) {
            found.push(p);
        }
    }
    found
}

pub fn find_exe(exe: &str, known: &[PathBuf], path: &[PathBuf]) -> Option<PathBuf> {
    find_all(exe, known, path).into_iter().next()
}

/// Windows paths are case-insensitive.
fn same_path(a: &Path, b: &Path) -> bool {
    a.as_os_str().eq_ignore_ascii_case(b.as_os_str())
}

/// Runs a program and returns its trimmed first line of stdout, or None if it failed.
pub fn first_line_of(program: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().next()?.trim();
    (!line.is_empty()).then(|| line.to_string())
}

/// "v22.15.0" -> Some(22)
pub fn parse_node_major(version: &str) -> Option<u32> {
    let v = version.trim();
    v.strip_prefix('v').unwrap_or(v).split('.').next()?.parse().ok()
}

#[derive(Clone, Debug)]
pub struct Node {
    pub exe: PathBuf,
    pub version: String,
    pub major: u32,
    /// npm ships next to node.exe; running its JS entry point with node avoids npm's batch-file shim and a shell.
    pub npm_cli: Option<PathBuf>,
}

impl Node {
    pub fn usable(&self) -> bool {
        self.major >= MIN_NODE_MAJOR && self.npm_cli.is_some()
    }

    fn probe(exe: PathBuf) -> Option<Node> {
        let version = first_line_of(&exe, &["--version"])?;
        let major = parse_node_major(&version)?;
        let npm_cli = exe
            .parent()
            .map(|d| d.join(r"node_modules\npm\bin\npm-cli.js"))
            .filter(|p| p.is_file());
        Some(Node { exe, version, major, npm_cli })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Msvc {
    Ready,
    /// Visual Studio is installed but lacks the C++ tools or a Windows SDK.
    Incomplete { installer: PathBuf, install_path: PathBuf, product_id: String },
    Missing,
}

#[derive(Clone, Debug, Default)]
pub struct Rust {
    pub cargo: Option<PathBuf>,
    pub rustup: Option<PathBuf>,
    /// `cargo --version`, present only when a default toolchain works.
    pub cargo_version: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Environment {
    pub winget: Option<PathBuf>,
    pub webview2: Option<String>,
    pub msvc: Msvc,
    pub node: Option<Node>,
    pub rust: Rust,
    pub git: Option<PathBuf>,
}

impl Environment {
    pub fn detect(dirs: &Dirs) -> Self {
        let cargo = find_exe("cargo.exe", &[dirs.cargo_bin.join("cargo.exe")], &dirs.path);
        let cargo_version = cargo.as_deref().and_then(|c| first_line_of(c, &["--version"]));
        Environment {
            winget: find_exe(
                "winget.exe",
                &[dirs.local_app_data.join(r"Microsoft\WindowsApps\winget.exe")],
                &dirs.path,
            ),
            webview2: find_webview2(dirs),
            msvc: detect_msvc(dirs),
            node: detect_node(dirs),
            rust: Rust {
                cargo,
                rustup: find_exe("rustup.exe", &[dirs.cargo_bin.join("rustup.exe")], &dirs.path),
                cargo_version,
            },
            git: find_exe("git.exe", &[dirs.program_files.join(r"Git\cmd\git.exe")], &dirs.path),
        }
    }
}

/// Prefers the first Node.js that is new enough and has npm beside it; otherwise reports the first
/// one found so the user sees why it was rejected.
fn detect_node(dirs: &Dirs) -> Option<Node> {
    let known = [dirs.program_files.join(r"nodejs\node.exe")];
    let nodes: Vec<Node> = find_all("node.exe", &known, &dirs.path)
        .into_iter()
        .filter_map(Node::probe)
        .collect();
    nodes.iter().find(|n| n.usable()).or(nodes.first()).cloned()
}

/// Returns the installed WebView2 runtime version, machine-wide or per-user.
fn find_webview2(dirs: &Dirs) -> Option<String> {
    let rel = r"Microsoft\EdgeWebView\Application";
    [&dirs.program_files_x86, &dirs.program_files, &dirs.local_app_data]
        .iter()
        .find_map(|base| {
            fs::read_dir(base.join(rel))
                .ok()?
                .flatten()
                .filter(|e| e.path().join("msedgewebview2.exe").is_file())
                .filter_map(|e| e.file_name().into_string().ok())
                .max()
        })
}

fn detect_msvc(dirs: &Dirs) -> Msvc {
    let installer_dir = dirs.program_files_x86.join(r"Microsoft Visual Studio\Installer");
    let vswhere = installer_dir.join("vswhere.exe");
    if !vswhere.is_file() {
        return Msvc::Missing;
    }
    let query = |requires: Option<&str>, property: &str| {
        let mut args = vec!["-latest", "-products", "*"];
        if let Some(component) = requires {
            args.extend(["-requires", component]);
        }
        args.extend(["-property", property]);
        first_line_of(&vswhere, &args)
    };
    if query(Some(VC_TOOLS_COMPONENT), "installationPath").is_some() && has_windows_sdk(dirs) {
        return Msvc::Ready;
    }
    match (query(None, "installationPath"), query(None, "productId")) {
        (Some(path), Some(product_id)) => Msvc::Incomplete {
            installer: installer_dir.join("setup.exe"),
            install_path: PathBuf::from(path),
            product_id,
        },
        _ => Msvc::Missing,
    }
}

/// A Windows 10/11 SDK is usable when its x64 import libraries are present.
fn has_windows_sdk(dirs: &Dirs) -> bool {
    fs::read_dir(dirs.program_files_x86.join(r"Windows Kits\10\Lib"))
        .map(|versions| {
            versions
                .flatten()
                .any(|v| v.path().join(r"um\x64\kernel32.lib").is_file())
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aegis-launcher-detect-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parses_node_versions() {
        assert_eq!(parse_node_major("v22.15.0"), Some(22));
        assert_eq!(parse_node_major(" v20.0.0\r\n"), Some(20));
        assert_eq!(parse_node_major("18.1.0"), Some(18));
        assert_eq!(parse_node_major("garbage"), None);
    }

    #[test]
    fn node_needs_version_and_npm() {
        let node = |major, npm: bool| Node {
            exe: PathBuf::from(r"C:\n\node.exe"),
            version: format!("v{major}.0.0"),
            major,
            npm_cli: npm.then(|| PathBuf::from(r"C:\n\npm-cli.js")),
        };
        assert!(node(20, true).usable());
        assert!(!node(18, true).usable());
        assert!(!node(22, false).usable());
    }

    #[test]
    fn find_all_prefers_path_then_known_and_ignores_relative_entries() {
        let dir = scratch("find");
        let (on_path, known) = (dir.join("on-path"), dir.join("known"));
        for d in [&on_path, &known] {
            fs::create_dir_all(d).unwrap();
            fs::write(d.join("tool.exe"), b"").unwrap();
        }
        let path = vec![PathBuf::from("relative-dir"), on_path.clone()];
        let found = find_all("tool.exe", &[known.join("tool.exe"), on_path.join("tool.exe")], &path);
        assert_eq!(found, vec![on_path.join("tool.exe"), known.join("tool.exe")]);
        assert_eq!(find_exe("missing.exe", &[], &path), None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn finds_newest_webview2_and_detects_sdk() {
        let dir = scratch("wv2");
        let dirs = Dirs { program_files_x86: dir.clone(), ..Default::default() };
        assert_eq!(find_webview2(&dirs), None);
        assert!(!has_windows_sdk(&dirs));
        for v in ["120.0.1.0", "130.0.2.0"] {
            let d = dir.join(r"Microsoft\EdgeWebView\Application").join(v);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("msedgewebview2.exe"), b"").unwrap();
        }
        assert_eq!(find_webview2(&dirs).as_deref(), Some("130.0.2.0"));
        let sdk = dir.join(r"Windows Kits\10\Lib\10.0.22621.0\um\x64");
        fs::create_dir_all(&sdk).unwrap();
        fs::write(sdk.join("kernel32.lib"), b"").unwrap();
        assert!(has_windows_sdk(&dirs));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn msvc_missing_without_vs_installer() {
        let dir = scratch("msvc");
        let dirs = Dirs { program_files_x86: dir.clone(), ..Default::default() };
        assert_eq!(detect_msvc(&dirs), Msvc::Missing);
        fs::remove_dir_all(dir).unwrap();
    }
}
