#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Thin command layer: every command forwards to `aegis_core::engine::Engine`,
//! which enforces all gates. Nothing here touches secrets directly.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use aegis_core::engine::{Engine, EngineOptions, LlmTest, Origin, PluginView, RunOutcome, SettingsUpdate, SettingsView, Status};
use aegis_core::mcp::McpStatus;
use aegis_core::os::{self, Instance, SingleInstance};
use aegis_core::registry::{GatePolicy, Plugin, Registry};
use aegis_core::tickets::TicketView;
use aegis_core::{AegisError, ErrorCode};
use serde_json::Value;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, State, WebviewUrl, WebviewWindowBuilder, WindowEvent};

type Cmd<T> = Result<T, AegisError>;
type EngineState<'a> = State<'a, Arc<Engine>>;

static APP: OnceLock<AppHandle> = OnceLock::new();

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
    match engine.change_running() {
        Some(tool) => format!("AegisWin: {state}, running {tool}"),
        None if unlocked && engine.background_active() => "AegisWin: unlocked, monitors running".into(),
        None => format!("AegisWin: {state}"),
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
    app.exit(0);
}

/// Tray menu: Open, Lock, Quit (ADR 0002 §4).
fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open AegisWin", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Lock", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("AegisWin")
        .menu(&Menu::with_items(app, &[&open, &lock, &quit])?)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main(app),
            "lock" => {
                let engine = app.state::<Arc<Engine>>().inner().clone();
                tauri::async_runtime::spawn(async move { engine.lock().await });
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

#[tauri::command]
async fn run_tool(engine: EngineState<'_>, plugin_id: String, tool_id: String, args: Value, pin: Option<String>) -> Cmd<RunOutcome> {
    engine.run_tool(Origin::Ui { pin }, &plugin_id, &tool_id, args).await
}

#[tauri::command]
async fn list_tickets(engine: EngineState<'_>) -> Cmd<Vec<TicketView>> {
    Ok(engine.list_tickets())
}

#[tauri::command]
async fn decide_ticket(engine: EngineState<'_>, ticket_id: String, approve: bool, pin: String, comment: Option<String>) -> Cmd<TicketView> {
    engine.decide_ticket(&ticket_id, approve, pin, comment, "app").await
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
    // Stop the MCP server first so the elevated copy can bind the same port.
    engine.lock().await;
    // Let go of this install before the elevated copy starts and checks it.
    drop(claim.0.lock().unwrap().take());
    let reclaim = || {
        if let Ok(Instance::First(guard)) = claim_instance() {
            *claim.0.lock().unwrap() = Some(guard);
        }
    };
    match aegis_core::os::relaunch_elevated() {
        Ok(()) => {
            app.exit(0);
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
    let data_dir = data_dir();
    let engine = Engine::new(&data_dir, registry(), EngineOptions::default());
    let app = tauri::Builder::default()
        .manage(engine)
        .manage(InstanceClaim(Mutex::new(claim)))
        .on_window_event(|window, event| {
            // With a monitor running, closing hides to the tray; otherwise it quits as before.
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.state::<Arc<Engine>>().background_active() {
                    api.prevent_close();
                    let _ = window.hide();
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
            run_tool,
            list_tickets,
            decide_ticket,
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
            // Removes the firewall rule and stops background sampling on a clean exit.
            let engine = handle.state::<Arc<Engine>>().inner().clone();
            tauri::async_runtime::block_on(engine.lock());
        }
    });
}
