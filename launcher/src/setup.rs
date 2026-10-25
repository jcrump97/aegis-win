//! Turns what `detect` found into a list of requirements, and installs what is missing.

use crate::detect::{Environment, Msvc, MIN_NODE_MAJOR};
use std::path::PathBuf;
use std::process::Command;

pub const WEBVIEW2_ID: &str = "Microsoft.EdgeWebView2Runtime";
pub const BUILD_TOOLS_ID: &str = "Microsoft.VisualStudio.2022.BuildTools";
pub const NODE_ID: &str = "OpenJS.NodeJS.LTS";
pub const RUSTUP_ID: &str = "Rustlang.Rustup";
/// winget passes this to the Visual Studio bootstrapper in place of its defaults.
const BUILD_TOOLS_OVERRIDE: &str =
    "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended";
const RUST_TOOLCHAIN: &str = "stable-x86_64-pc-windows-msvc";

#[derive(Clone, Debug, PartialEq)]
pub enum Fix {
    Winget { id: &'static str, override_args: Option<&'static str> },
    /// Add the C++ workload (which brings a Windows SDK) to an existing Visual Studio install.
    VsModify { installer: PathBuf, install_path: PathBuf, workload: &'static str },
    RustupDefault { rustup: PathBuf },
}

impl Fix {
    pub fn describe(&self) -> String {
        match self {
            Fix::Winget { id, .. } => format!("install with winget ({id})"),
            Fix::VsModify { workload, .. } => format!("add {workload} with Visual Studio Installer"),
            Fix::RustupDefault { .. } => format!("rustup default {RUST_TOOLCHAIN}"),
        }
    }

    pub fn uses_winget(&self) -> bool {
        matches!(self, Fix::Winget { .. })
    }

    /// Program and argument vector. Every program is an absolute path and nothing goes through a shell.
    pub fn command(&self, winget: Option<&PathBuf>) -> Option<(PathBuf, Vec<String>)> {
        match self {
            Fix::Winget { id, override_args } => {
                let mut args: Vec<String> = [
                    "install", "--id", id, "--exact", "--source", "winget",
                    "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity",
                ]
                .map(String::from)
                .to_vec();
                if let Some(o) = override_args {
                    args.extend(["--override".to_string(), o.to_string()]);
                }
                Some((winget?.clone(), args))
            }
            Fix::VsModify { installer, install_path, workload } => Some((
                installer.clone(),
                vec![
                    "modify".into(),
                    "--installPath".into(),
                    install_path.display().to_string(),
                    "--add".into(),
                    workload.to_string(),
                    "--includeRecommended".into(),
                    "--passive".into(),
                    "--norestart".into(),
                ],
            )),
            Fix::RustupDefault { rustup } => {
                Some((rustup.clone(), vec!["default".into(), RUST_TOOLCHAIN.into()]))
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Item {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
    pub fix: Option<Fix>,
    /// Where to get it by hand if the automatic fix fails.
    pub manual: &'static str,
}

impl Item {
    fn ok(name: &'static str, detail: impl Into<String>, manual: &'static str) -> Self {
        Item { name, ok: true, detail: detail.into(), fix: None, manual }
    }
    fn missing(name: &'static str, detail: impl Into<String>, fix: Fix, manual: &'static str) -> Self {
        Item { name, ok: false, detail: detail.into(), fix: Some(fix), manual }
    }
}

/// Requirements in install order: the C++ tools go before Rust so rustup finds a linker.
pub fn assess(env: &Environment) -> Vec<Item> {
    let mut items = Vec::new();

    const WV2_MANUAL: &str = "https://developer.microsoft.com/microsoft-edge/webview2/";
    items.push(match &env.webview2 {
        Some(v) => Item::ok("WebView2 Runtime", v.clone(), WV2_MANUAL),
        None => Item::missing("WebView2 Runtime", "not found", winget(WEBVIEW2_ID), WV2_MANUAL),
    });

    const VS_MANUAL: &str =
        "https://visualstudio.microsoft.com/visual-cpp-build-tools/ (choose \"Desktop development with C++\")";
    items.push(match &env.msvc {
        Msvc::Ready => Item::ok("C++ Build Tools", "installed", VS_MANUAL),
        Msvc::Incomplete { installer, install_path, product_id } => Item::missing(
            "C++ Build Tools",
            "Visual Studio is installed but is missing the C++ tools or Windows SDK",
            Fix::VsModify {
                installer: installer.clone(),
                install_path: install_path.clone(),
                workload: workload_for(product_id),
            },
            VS_MANUAL,
        ),
        Msvc::Missing => Item::missing(
            "C++ Build Tools",
            "not found",
            Fix::Winget { id: BUILD_TOOLS_ID, override_args: Some(BUILD_TOOLS_OVERRIDE) },
            VS_MANUAL,
        ),
    });

    const NODE_MANUAL: &str = "https://nodejs.org (LTS version)";
    items.push(match &env.node {
        Some(n) if n.usable() => Item::ok("Node.js", n.version.clone(), NODE_MANUAL),
        Some(n) if n.major < MIN_NODE_MAJOR => Item::missing(
            "Node.js",
            format!("{} is too old (need {MIN_NODE_MAJOR} or newer)", n.version),
            winget(NODE_ID),
            NODE_MANUAL,
        ),
        Some(n) => Item::missing(
            "Node.js",
            format!("{} found, but npm is not installed next to it", n.version),
            winget(NODE_ID),
            NODE_MANUAL,
        ),
        None => Item::missing("Node.js", "not found", winget(NODE_ID), NODE_MANUAL),
    });

    const RUST_MANUAL: &str = "https://rustup.rs";
    let rust = &env.rust;
    items.push(match (&rust.cargo_version, &rust.rustup) {
        (Some(v), _) => Item::ok("Rust", v.clone(), RUST_MANUAL),
        (None, Some(rustup)) if rust.cargo.is_some() => Item::missing(
            "Rust",
            "installed, but no default toolchain is set",
            Fix::RustupDefault { rustup: rustup.clone() },
            RUST_MANUAL,
        ),
        _ => Item::missing("Rust", "not found", winget(RUSTUP_ID), RUST_MANUAL),
    });

    items
}

fn winget(id: &'static str) -> Fix {
    Fix::Winget { id, override_args: None }
}

/// Build Tools calls its C++ workload "VCTools"; full Visual Studio calls it "NativeDesktop".
pub fn workload_for(product_id: &str) -> &'static str {
    if product_id.ends_with("BuildTools") {
        "Microsoft.VisualStudio.Workload.VCTools"
    } else {
        "Microsoft.VisualStudio.Workload.NativeDesktop"
    }
}

/// Runs one fix with the console attached so the user sees installer progress.
pub fn apply(fix: &Fix, env: &Environment) -> Result<(), String> {
    let (program, args) = fix
        .command(env.winget.as_ref())
        .ok_or_else(|| "winget is not available".to_string())?;
    let status = Command::new(&program)
        .args(&args)
        .status()
        .map_err(|e| format!("couldn't start {}: {e}", program.display()))?;
    // winget returns non-zero for "already installed" too, so the caller re-detects instead of trusting this.
    if status.success() {
        Ok(())
    } else {
        Err(format!("{} exited with {status}", program.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{Node, Rust};

    fn ready_env() -> Environment {
        Environment {
            winget: Some(PathBuf::from(r"C:\Users\u\AppData\Local\Microsoft\WindowsApps\winget.exe")),
            webview2: Some("130.0.0.0".into()),
            msvc: Msvc::Ready,
            node: Some(Node {
                exe: PathBuf::from(r"C:\Program Files\nodejs\node.exe"),
                version: "v22.15.0".into(),
                major: 22,
                npm_cli: Some(PathBuf::from(r"C:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js")),
            }),
            rust: Rust {
                cargo: Some(PathBuf::from(r"C:\Users\u\.cargo\bin\cargo.exe")),
                rustup: Some(PathBuf::from(r"C:\Users\u\.cargo\bin\rustup.exe")),
                cargo_version: Some("cargo 1.99.1".into()),
            },
            git: None,
        }
    }

    fn fixes(env: &Environment) -> Vec<Fix> {
        assess(env).into_iter().filter_map(|i| i.fix).collect()
    }

    #[test]
    fn ready_machine_needs_nothing() {
        let items = assess(&ready_env());
        assert_eq!(items.len(), 4);
        assert!(items.iter().all(|i| i.ok && i.fix.is_none()));
    }

    #[test]
    fn bare_machine_installs_everything_in_order() {
        let env = Environment {
            webview2: None,
            msvc: Msvc::Missing,
            node: None,
            rust: Rust::default(),
            ..ready_env()
        };
        let ids: Vec<&str> = fixes(&env)
            .iter()
            .map(|f| match f {
                Fix::Winget { id, .. } => *id,
                other => panic!("unexpected fix {other:?}"),
            })
            .collect();
        assert_eq!(ids, [WEBVIEW2_ID, BUILD_TOOLS_ID, NODE_ID, RUSTUP_ID]);
    }

    #[test]
    fn old_node_and_missing_toolchain_get_targeted_fixes() {
        let mut env = ready_env();
        env.node.as_mut().unwrap().major = 18;
        env.rust.cargo_version = None;
        let f = fixes(&env);
        assert_eq!(f[0], winget(NODE_ID));
        assert!(matches!(&f[1], Fix::RustupDefault { .. }));
    }

    #[test]
    fn incomplete_visual_studio_is_modified_not_reinstalled() {
        let mut env = ready_env();
        env.msvc = Msvc::Incomplete {
            installer: PathBuf::from(r"C:\VSI\setup.exe"),
            install_path: PathBuf::from(r"C:\VS\BuildTools"),
            product_id: "Microsoft.VisualStudio.Product.BuildTools".into(),
        };
        let (program, args) = fixes(&env)[0].command(None).unwrap();
        assert_eq!(program, PathBuf::from(r"C:\VSI\setup.exe"));
        assert_eq!(args[..3], ["modify", "--installPath", r"C:\VS\BuildTools"]);
        assert!(args.contains(&"Microsoft.VisualStudio.Workload.VCTools".to_string()));
        assert_eq!(workload_for("Microsoft.VisualStudio.Product.Community"), "Microsoft.VisualStudio.Workload.NativeDesktop");
    }

    #[test]
    fn winget_commands_use_an_absolute_path_and_argv() {
        let env = ready_env();
        let fix = Fix::Winget { id: BUILD_TOOLS_ID, override_args: Some(BUILD_TOOLS_OVERRIDE) };
        let (program, args) = fix.command(env.winget.as_ref()).unwrap();
        assert!(program.is_absolute());
        assert_eq!(args[..3], ["install", "--id", BUILD_TOOLS_ID]);
        // The override travels as a single argument, never split or re-parsed by a shell.
        assert_eq!(args.last().unwrap(), BUILD_TOOLS_OVERRIDE);
        assert_eq!(winget(NODE_ID).command(None), None, "no winget, no command");
    }
}
