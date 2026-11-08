#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Thin command layer: every command forwards to `aegis_core::engine::Engine`,
//! which enforces all gates. Nothing here touches secrets directly.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use aegis_core::engine::{Engine, EngineOptions, LlmTest, Origin, PluginView, RunOutcome, SettingsUpdate, SettingsView, Status};
use aegis_core::mcp::McpStatus;
use aegis_core::os::{self, Instance, SingleInstance};
use aegis_core::registry::{ExitReason, GatePolicy, Launch, Plugin, Registry};
use aegis_core::plan::PlanOrigin;
use aegis_core::tickets::TicketView;
use aegis_core::{AegisError, ErrorCode};
use serde_json::Value;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, State, WebviewUrl, WebviewWindowBuilder, WindowEvent};

type Cmd<T> = Result<T, AegisError>;
type EngineState<'a> = State<'a, Arc<Engine>>;

static APP: OnceLock<AppHandle> = OnceLock::new();

/// Set when the owner quits (tray Quit, closing the window, the elevated
/// restart). An exit without it is Windows ending the session, which the
/// history records as a shutdown.
static QUIT_REQUESTED: AtomicBool = AtomicBool::new(false);

fn request_quit(app: &AppHandle) {
    QUIT_REQUESTED.store(true, Ordering::SeqCst);
    app.exit(0);
}

/// This install's single-instance claim, held for the life of the process.
/// Released only for the elevated restart, so the elevated copy can start.
struct InstanceClaim(Mutex<Option<SingleInstance>>);

/// Claims this install; a later launch shows this copy's window instead.
fn claim_instance() -> std::io::Result<Instance> {
    os::single_instance(&os::install_key(&data_dir()), || {
        if let Some(app) = APP.get() {
            show_main(app);
        }
    })
}

fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn tray_text(engine: &Engine) -> String {
    let unlocked = engine.status().unlocked;
    let state = if unlocked { "unlocked" } else { "locked" };
    let paused = if engine.monitoring_paused() { ", monitoring paused" } else { "" };
    match engine.change_running() {
        Some(tool) => format!("AegisWin: {state}, running {tool}{paused}"),
        None if unlocked && engine.background_active() => format!("AegisWin: unlocked, monitors running{paused}"),
        None if engine.locked_monitoring() => format!("AegisWin: locked, monitoring{paused}"),
        None => format!("AegisWin: {state}{paused}"),
    }
}

fn pause_label(paused: bool) -> &'static str {
    if paused {
        "Resume monitoring"
    } else {
        "Pause monitoring"
    }
}

/// Quitting while a change runs can leave it half done, so ask first.
fn quit_app(app: &AppHandle) {
    let running = app.state::<Arc<Engine>>().change_running();
    if let Some(tool) = running {
        let text = format!("{tool} is still running. Quitting now may leave the change half done.\n\nQuit anyway?");
        if !os::confirm("Quit AegisWin?", &text) {
            return;
        }
    }
    request_quit(app);
}

/// Tray menu: Open, Lock, Pause monitoring, Quit (ADR 0002 §4).
fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open AegisWin", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Lock", true, None::<&str>)?;
    // A pause kept in the runtime file carries over a restart.
    let paused = app.state::<Arc<Engine>>().monitoring_paused();
    let pause = MenuItem::with_id(app, "pause", pause_label(paused), true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let pause_item = pause.clone();
    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("AegisWin")
        .menu(&Menu::with_items(app, &[&open, &lock, &pause, &quit])?)
        .show_menu_on_left_click(false)
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "open" => show_main(app),
            "lock" => {
                let engine = app.state::<Arc<Engine>>().inner().clone();
                tauri::async_runtime::spawn(async move { engine.lock().await });
            }
            // No PIN: only the person at this PC can reach the tray.
            "pause" => {
                let engine = app.state::<Arc<Engine>>();
                let paused = !engine.monitoring_paused();
                engine.set_monitoring_paused(paused);
                let _ = pause_item.set_text(pause_label(paused));
                if let Some(tray) = app.tray_by_id("main") {
                    let _ = tray.set_tooltip(Some(tray_text(&engine)));
                }
            }
            "quit" => quit_app(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

/// Every 5 seconds: idle auto-lock, and the tray tooltip shows the state.
fn start_idle_watch(app: AppHandle, engine: Arc<Engine>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        tauri::async_runtime::block_on(engine.lock_if_idle(Instant::now()));
        // Flushes history frames to disk every 30 seconds, even when nothing new is written.
        engine.history_tick();
        if let Some(tray) = app.tray_by_id("main") {
            let _ = tray.set_tooltip(Some(tray_text(&engine)));
        }
    });
}

/// Portable: everything lives in `data` next to the executable.
fn data_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("cannot locate aegis-win.exe");
    exe.parent().map(|dir| dir.join("data")).unwrap_or_else(|| PathBuf::from("data"))
}

fn registry() -> Registry {
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(aegis_plugin_event_logs::EventLogsPlugin::default()),
        Arc::new(aegis_plugin_windows_health::WindowsHealthPlugin::default()),
        Arc::new(aegis_plugin_usage_monitor::UsageMonitorPlugin::default()),
    ];
    Registry::new(plugins).expect("built-in plugin manifests are valid")
}

#[tauri::command]
async fn status(engine: EngineState<'_>) -> Cmd<Status> {
    Ok(engine.status())
}

#[tauri::command]
async fn setup_vault(engine: EngineState<'_>, pin: String) -> Cmd<Status> {
    engine.setup(pin).await
}

#[tauri::command]
async fn unlock_vault(engine: EngineState<'_>, pin: String) -> Cmd<Status> {
    engine.unlock(pin).await
}

#[tauri::command]
async fn lock_vault(engine: EngineState<'_>) -> Cmd<Status> {
    Ok(engine.lock().await)
}

/// Input in the app window (sent at most every 30 seconds) keeps the vault
/// unlocked; nothing an agent does can call this.
#[tauri::command]
async fn note_activity(engine: EngineState<'_>) -> Cmd<()> {
    engine.note_activity();
    Ok(())
}

#[tauri::command]
async fn change_pin(engine: EngineState<'_>, current: String, next: String) -> Cmd<()> {
    engine.change_pin(current, next).await
}

#[tauri::command]
async fn get_settings(engine: EngineState<'_>) -> Cmd<SettingsView> {
    engine.settings().await
}

#[tauri::command]
async fn update_settings(engine: EngineState<'_>, update: SettingsUpdate) -> Cmd<SettingsView> {
    engine.update_settings(update).await
}

#[tauri::command]
async fn set_llm_api_key(engine: EngineState<'_>, key: String) -> Cmd<()> {
    engine.set_llm_api_key(key)
}

#[tauri::command]
async fn test_llm(engine: EngineState<'_>) -> Cmd<LlmTest> {
    engine.test_llm().await
}

#[tauri::command]
async fn list_plugins(engine: EngineState<'_>) -> Cmd<Vec<PluginView>> {
    engine.plugins()
}

#[tauri::command]
async fn set_installed(engine: EngineState<'_>, selection: BTreeMap<String, Vec<String>>) -> Cmd<Vec<PluginView>> {
    engine.set_installed(selection)
}

#[tauri::command]
async fn set_gate_policy(engine: EngineState<'_>, plugin_id: String, tool_id: String, policy: GatePolicy, pin: Option<String>) -> Cmd<GatePolicy> {
    engine.set_gate_policy(&plugin_id, &tool_id, policy, pin).await
}

#[tauri::command]
async fn grant_llm_trust(engine: EngineState<'_>, plugin_id: String, pin: String) -> Cmd<()> {
    engine.grant_llm_trust(&plugin_id, pin).await
}

#[tauri::command]
async fn revoke_llm_trust(engine: EngineState<'_>, plugin_id: String) -> Cmd<()> {
    engine.revoke_llm_trust(&plugin_id)
}

/// Rewrites a set-aside runtime file from the vault (app only, never MCP).
#[tauri::command]
async fn rewrite_runtime(engine: EngineState<'_>, plugin_id: String) -> Cmd<()> {
    engine.rewrite_runtime_from_vault(&plugin_id)
}

/// Closes the banner about the gap before a resume at launch.
#[tauri::command]
async fn dismiss_resume_notice(engine: EngineState<'_>, plugin_id: String) -> Cmd<()> {
    engine.dismiss_resume_notice(&plugin_id);
    Ok(())
}

#[tauri::command]
async fn run_tool(engine: EngineState<'_>, plugin_id: String, tool_id: String, args: Value, pin: Option<String>) -> Cmd<RunOutcome> {
    engine.run_tool(Origin::Ui { pin }, &plugin_id, &tool_id, args).await
}

#[tauri::command]
async fn list_tickets(engine: EngineState<'_>) -> Cmd<Vec<TicketView>> {
    Ok(engine.list_tickets())
}

#[tauri::command]
async fn decide_ticket(
    engine: EngineState<'_>,
    ticket_id: String,
    approve: bool,
    pin: String,
    comment: Option<String>,
    plan_hash: Option<String>,
) -> Cmd<TicketView> {
    engine.decide(&ticket_id, approve, pin, comment, "app", plan_hash.as_deref()).await
}

/// Opens a plan the owner built in the app. Nothing runs until it is approved
/// with the PIN on the Approvals tab, like any other plan.
#[tauri::command]
async fn propose_plan(engine: EngineState<'_>, request: Value) -> Cmd<TicketView> {
    engine.propose_plan(PlanOrigin::Owner, request).await
}

/// Withdraws a request or stops a plan before its next step; needs no PIN.
#[tauri::command]
async fn cancel_ticket(engine: EngineState<'_>, ticket_id: String) -> Cmd<TicketView> {
    engine.cancel_ticket(&ticket_id)
}

#[tauri::command]
async fn start_mcp(engine: EngineState<'_>) -> Cmd<McpStatus> {
    engine.start_mcp().await
}

#[tauri::command]
async fn stop_mcp(engine: EngineState<'_>) -> Cmd<McpStatus> {
    engine.disable_mcp().await
}

#[tauri::command]
async fn reveal_mcp_token(engine: EngineState<'_>, pin: String) -> Cmd<String> {
    engine.reveal_mcp_token(pin).await
}

#[tauri::command]
async fn rotate_mcp_token(engine: EngineState<'_>) -> Cmd<()> {
    engine.rotate_mcp_token()
}

/// Starts an elevated copy through UAC, then exits this one.
#[tauri::command]
async fn restart_as_admin(app: tauri::AppHandle, engine: EngineState<'_>, claim: State<'_, InstanceClaim>) -> Cmd<()> {
    if engine.elevated() {
        return Err(AegisError::new(ErrorCode::Conflict, "AegisWin is already running as administrator."));
    }
    // Restarting would cut the running change off; waiting ones are cancelled by the lock below.
    if let Some(tool) = engine.change_running() {
        return Err(AegisError::new(ErrorCode::Conflict, format!("Wait for {tool} to finish before restarting as administrator.")));
    }
    // Stop the MCP server first so the elevated copy can bind the same port,
    // and stop monitoring here so only one copy writes the history.
    engine.exit(ExitReason::Quit).await;
    // Let go of this install before the elevated copy starts and checks it.
    drop(claim.0.lock().unwrap().take());
    let reclaim = || {
        if let Ok(Instance::First(guard)) = claim_instance() {
            *claim.0.lock().unwrap() = Some(guard);
        }
    };
    match aegis_core::os::relaunch_elevated() {
        Ok(()) => {
            request_quit(&app);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
            reclaim();
            Err(AegisError::new(ErrorCode::AccessDenied, "The administrator prompt was cancelled. AegisWin is locked; unlock to continue."))
        }
        Err(e) => {
            reclaim();
            Err(AegisError::failed(format!("Could not restart as administrator: {e}")))
        }
    }
}

fn main() {
    // One copy per install: a second launch shows the running one and exits.
    let claim = match claim_instance() {
        Ok(Instance::First(guard)) => Some(guard),
        Ok(Instance::AlreadyRunning) => return,
        // The check never stops AegisWin from starting.
        Err(_) => None,
    };
    // `--background` is the Startup shortcut (ADR 0002 §6): no window, tray only.
    let background = std::env::args().skip(1).any(|a| a == "--background");
    let data_dir = data_dir();
    let engine = Engine::new(&data_dir, registry(), EngineOptions::default());
    // Every launch resumes running monitors in *locked, monitoring*.
    let resumed = engine.resume_at_launch(if background { Launch::Autostart } else { Launch::Manual });
    if background && !resumed {
        // Nothing to monitor: a sign-in launch stays out of the way.
        return;
    }
    let app = tauri::Builder::default()
        .manage(engine)
        .manage(InstanceClaim(Mutex::new(claim)))
        .on_window_event(|window, event| {
            // With a monitor running, closing hides to the tray; otherwise it quits as before.
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.state::<Arc<Engine>>().background_active() {
                    api.prevent_close();
                    let _ = window.hide();
                } else {
                    // Closing the last window quits.
                    QUIT_REQUESTED.store(true, Ordering::SeqCst);
                }
            }
        })
        .setup(move |app| {
            let _ = APP.set(app.handle().clone());
            build_tray(app)?;
            start_idle_watch(app.handle().clone(), app.state::<Arc<Engine>>().inner().clone());
            let title = if aegis_core::os::is_elevated() { "AegisWin (Administrator)" } else { "AegisWin" };
            WebviewWindowBuilder::new(app, "main", WebviewUrl::default())
                .title(title)
                .inner_size(1180.0, 800.0)
                .min_inner_size(900.0, 620.0)
                .visible(!background)
                // Keep WebView2's cache and storage in ./data too, so the app stays portable.
                .data_directory(data_dir.join("webview"))
                .build()?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status,
            setup_vault,
            unlock_vault,
            lock_vault,
            note_activity,
            change_pin,
            get_settings,
            update_settings,
            set_llm_api_key,
            test_llm,
            list_plugins,
            set_installed,
            set_gate_policy,
            grant_llm_trust,
            revoke_llm_trust,
            rewrite_runtime,
            dismiss_resume_notice,
            run_tool,
            list_tickets,
            decide_ticket,
            cancel_ticket,
            propose_plan,
            start_mcp,
            stop_mcp,
            reveal_mcp_token,
            rotate_mcp_token,
            restart_as_admin,
        ])
        .build(tauri::generate_context!())
        .expect("error while building AegisWin");
    app.run(|handle, event| {
        if let tauri::RunEvent::Exit = event {
            // Writes the clean-stop record (quit, or Windows ending the session),
            // removes the firewall rule, and stops all background work.
            let reason = if QUIT_REQUESTED.load(Ordering::SeqCst) { ExitReason::Quit } else { ExitReason::Shutdown };
            let engine = handle.state::<Arc<Engine>>().inner().clone();
            tauri::async_runtime::block_on(engine.exit(reason));
        }
    });
}
