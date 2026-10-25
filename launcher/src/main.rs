//! `Start AegisWin.exe`: checks this PC, installs what AegisWin needs, builds it if the sources
//! changed, and starts it. Double-click it from the repository root.

mod detect;
mod project;
mod setup;

use detect::{Dirs, Environment};
use setup::{Fix, Item};
use std::ffi::OsStr;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const HELP: &str = "\
Start AegisWin: checks this PC, installs what AegisWin needs, then builds and starts it.

Usage: \"Start AegisWin.exe\" [options]

  --check     Only report what is installed and what would happen. Changes nothing.
  --yes       Install missing tools without asking first.
  --rebuild   Rebuild the app even if nothing changed.
  --dev       Start in development mode with hot reload (npm run tauri:dev).
  --help      Show this help.
";

#[derive(Debug, Default, PartialEq)]
struct Options {
    check: bool,
    yes: bool,
    rebuild: bool,
    dev: bool,
}

/// Ok(None) means --help.
fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Option<Options>, String> {
    let mut o = Options::default();
    for arg in args {
        match arg.as_str() {
            "--check" => o.check = true,
            "--yes" | "-y" => o.yes = true,
            "--rebuild" => o.rebuild = true,
            "--dev" => o.dev = true,
            "--help" | "-h" | "/?" => return Ok(None),
            other => return Err(format!("unknown option: {other} (try --help)")),
        }
    }
    Ok(Some(o))
}

enum Outcome {
    /// The app was started; close the console right away.
    Launched,
    /// Show the message and keep the window open so it can be read.
    Stopped,
}

fn main() -> ExitCode {
    let opts = match parse_args(std::env::args().skip(1)) {
        Ok(Some(o)) => o,
        Ok(None) => {
            print!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    println!("AegisWin launcher\n");
    let code = match run(&opts) {
        Ok(Outcome::Launched) => return ExitCode::SUCCESS,
        Ok(Outcome::Stopped) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("\nSetup stopped: {message}");
            ExitCode::FAILURE
        }
    };
    pause_if_double_clicked();
    code
}

fn run(opts: &Options) -> Result<Outcome, String> {
    let root = locate_root()?;
    println!("Project folder: {}\n", root.display());

    let dirs = Dirs::from_env();
    println!("Checking this PC...");
    let mut env = Environment::detect(&dirs);
    let items = setup::assess(&env);
    print_items(&items);

    if opts.check {
        report_project(&root);
        return Ok(Outcome::Stopped);
    }
    if items.iter().any(|i| !i.ok) {
        install_missing(&dirs, &mut env, &items, opts.yes)?;
    }

    let node = env.node.clone().filter(|n| n.usable()).ok_or("Node.js is not ready")?;
    let npm_cli = node.npm_cli.clone().ok_or("npm is not installed")?;
    let tool_dirs: Vec<PathBuf> = [Some(&node.exe), env.rust.cargo.as_ref()]
        .into_iter()
        .flatten()
        .filter_map(|exe| exe.parent().map(Path::to_path_buf))
        .collect();
    let path_env = project::child_path(&tool_dirs, &dirs.path);

    enable_git_hooks(env.git.as_deref(), &root);

    if project::needs_npm_install(&root) {
        step("Installing JavaScript packages (npm ci)");
        run_tool("npm ci", &node.exe, &[npm_cli.as_os_str(), "ci".as_ref(), "--no-audit".as_ref(), "--no-fund".as_ref()], &root, &path_env)?;
    }
    let tauri_cli = root.join(project::TAURI_CLI);

    if opts.dev {
        if std::net::TcpListener::bind(("127.0.0.1", 1420)).is_err() {
            return Err("port 1420 is already in use. Stop `npm run dev` or another `tauri dev` first.".into());
        }
        step("Starting AegisWin in development mode (close the app window to stop)");
        run_tool("tauri dev", &node.exe, &[tauri_cli.as_os_str(), "dev".as_ref()], &root, &path_env)?;
        return Ok(Outcome::Launched);
    }

    let app = root.join(project::APP_EXE);
    if project::is_running(&app) {
        println!("\nAegisWin is already running. Close it and start the launcher again to pick up changes.");
        return Ok(Outcome::Stopped);
    }
    if opts.rebuild || project::needs_build(&root) {
        step("Building AegisWin (the first build takes several minutes; later ones are quick)");
        run_tool("tauri build", &node.exe, &[tauri_cli.as_os_str(), "build".as_ref()], &root, &path_env)?;
    } else {
        println!("\nAegisWin is up to date.");
    }

    launch(&app)?;
    println!("\nAegisWin is starting.");
    Ok(Outcome::Launched)
}

/// The exe normally sits in the repository root; `cargo run` from launcher\ also works.
fn locate_root() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("can't find this program's location: {e}"))?;
    exe.parent()
        .and_then(project::find_root)
        .or_else(|| std::env::current_dir().ok().as_deref().and_then(project::find_root))
        .ok_or_else(|| {
            "can't find the AegisWin project folder. Keep \"Start AegisWin.exe\" in the AegisWin folder, next to package.json.".into()
        })
}

fn print_items(items: &[Item]) {
    for i in items {
        let tag = if i.ok { " ok " } else { "need" };
        println!("  [{tag}]  {:<18} {}", i.name, i.detail);
    }
}

fn report_project(root: &Path) {
    let npm = if project::needs_npm_install(root) { "need to install" } else { "installed" };
    let build = if project::needs_build(root) { "needs a build" } else { "up to date" };
    println!("\n  JavaScript packages: {npm}\n  AegisWin app:        {build}");
    println!("\n--check made no changes.");
}

fn install_missing(dirs: &Dirs, env: &mut Environment, items: &[Item], assume_yes: bool) -> Result<(), String> {
    let missing: Vec<&Item> = items.iter().filter(|i| !i.ok).collect();
    let manual = |list: &[&Item]| -> String {
        list.iter().map(|i| format!("\n  - {}: {}", i.name, i.manual)).collect()
    };
    if env.winget.is_none() && missing.iter().any(|i| i.fix.as_ref().is_some_and(Fix::uses_winget)) {
        return Err(format!(
            "winget isn't available, so the launcher can't install tools for you.\n\
             Install \"App Installer\" from the Microsoft Store and run the launcher again, or install these yourself:{}",
            manual(&missing)
        ));
    }

    println!("\nAegisWin needs these first:");
    for i in &missing {
        if let Some(fix) = &i.fix {
            println!("  - {}: {}", i.name, fix.describe());
        }
    }
    println!(
        "\nInstalling accepts each package's license terms. Windows may ask for permission for some installers."
    );
    if missing.iter().any(|i| i.name == "C++ Build Tools") {
        println!("The C++ Build Tools are a large download (several GB) and can take 10 to 20 minutes.");
    }
    if !assume_yes && !confirm("Install them now? [Y/n] ") {
        return Err(format!("nothing was installed. Run the launcher again when you're ready, or install them yourself:{}", manual(&missing)));
    }

    // Some fixes only become possible after another succeeds (rustup is installed, then it needs a
    // default toolchain), so try twice, never repeating a fix that was already attempted.
    let mut attempted: Vec<Fix> = Vec::new();
    for _ in 0..2 {
        let pending: Vec<Fix> = setup::assess(env)
            .into_iter()
            .filter_map(|i| i.fix)
            .filter(|f| !attempted.contains(f))
            .collect();
        if pending.is_empty() {
            break;
        }
        for fix in pending {
            step(&fix.describe());
            if let Err(e) = setup::apply(&fix, env) {
                println!("    note: {e}");
            }
            attempted.push(fix);
        }
        *env = Environment::detect(dirs);
    }

    let after = setup::assess(env);
    print_items(&after);
    let still: Vec<&Item> = after.iter().filter(|i| !i.ok).collect();
    if !still.is_empty() {
        return Err(format!(
            "some tools are still missing. If an installer just finished, restart Windows and run the launcher again. \
             Otherwise install these yourself:{}",
            manual(&still)
        ));
    }
    println!("\nEverything AegisWin needs is installed.");
    Ok(())
}

/// Git doesn't carry core.hooksPath into a clone, so turn the repo's hooks on once. Skipped for
/// downloads without .git or machines without git; it only matters to contributors.
fn enable_git_hooks(git: Option<&Path>, root: &Path) {
    let Some(git) = git else { return };
    if !detect::exists(&root.join(".git")) {
        return;
    }
    let git_config = |args: &[&str]| {
        Command::new(git).arg("-C").arg(root).arg("config").args(args).output()
    };
    let already_set = git_config(&["--get", "core.hooksPath"]).is_ok_and(|o| o.status.success());
    if !already_set && git_config(&["core.hooksPath", ".githooks"]).is_ok_and(|o| o.status.success()) {
        println!("\nTurned on the project's git hooks (core.hooksPath = .githooks).");
    }
}

fn step(title: &str) {
    println!("\n==> {title}");
}

/// Runs a tool by absolute path with an argument vector (no shell), showing its output.
fn run_tool(label: &str, program: &Path, args: &[&OsStr], cwd: &Path, path_env: &OsStr) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .env("PATH", path_env)
        .status()
        .map_err(|e| format!("couldn't start {}: {e}", program.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{label}` failed ({status}). The messages above say what went wrong."))
    }
}

/// Starts the app on its own so it keeps running after this console closes.
fn launch(app: &Path) -> Result<(), String> {
    let mut cmd = Command::new(app);
    cmd.current_dir(app.parent().unwrap_or(Path::new(".")))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    cmd.spawn()
        .map(drop)
        .map_err(|e| format!("couldn't start {}: {e}", app.display()))
}

/// Defaults to yes on a bare Enter; no input (closed stdin) means no.
fn confirm(prompt: &str) -> bool {
    print!("{prompt}");
    let _ = io::stdout().flush();
    let mut line = String::new();
    match io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => false,
        Ok(_) => is_yes(&line),
    }
}

fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "" | "y" | "yes")
}

/// Keeps the window open when Explorer created this console for us (double-click), so messages
/// can be read. From an existing terminal it returns straight away.
fn pause_if_double_clicked() {
    if own_console() {
        print!("\nPress Enter to close this window.");
        let _ = io::stdout().flush();
        let _ = io::stdin().lock().read_line(&mut String::new());
    }
}

#[cfg(windows)]
fn own_console() -> bool {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetConsoleProcessList(list: *mut u32, count: u32) -> u32;
    }
    let mut ids = [0u32; 2];
    // SAFETY: the buffer is valid for `ids.len()` entries; the call only writes within it.
    let attached = unsafe { GetConsoleProcessList(ids.as_mut_ptr(), ids.len() as u32) };
    attached == 1
}

#[cfg(not(windows))]
fn own_console() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_options() {
        assert_eq!(parse_args(args(&[])), Ok(Some(Options::default())));
        assert_eq!(
            parse_args(args(&["--check", "-y", "--rebuild", "--dev"])),
            Ok(Some(Options { check: true, yes: true, rebuild: true, dev: true }))
        );
        assert_eq!(parse_args(args(&["--help"])), Ok(None));
        assert!(parse_args(args(&["--nope"])).is_err());
    }

    #[test]
    fn enter_means_yes() {
        for yes in ["\r\n", "y\n", "YES\r\n"] {
            assert!(is_yes(yes), "{yes:?}");
        }
        for no in ["n\n", "no", "later"] {
            assert!(!is_yes(no), "{no:?}");
        }
    }
}
