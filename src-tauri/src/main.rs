#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Thin command layer: every command forwards to `aegis_core::engine::Engine`,
//! which enforces all gates. Nothing here touches secrets directly.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use aegis_core::engine::{Engine, EngineOptions, LlmTest, Origin, PluginView, RunOutcome, SettingsUpdate, SettingsView, Status};
use aegis_core::mcp::McpStatus;
use aegis_core::registry::{GatePolicy, Plugin, Registry};
use aegis_core::tickets::TicketView;
use aegis_core::{AegisError, ErrorCode};
use serde_json::Value;
use tauri::{Manager, State, WebviewUrl, WebviewWindowBuilder};

type Cmd<T> = Result<T, AegisError>;
type EngineState<'a> = State<'a, Arc<Engine>>;

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
async fn restart_as_admin(app: tauri::AppHandle, engine: EngineState<'_>) -> Cmd<()> {
    if engine.elevated() {
        return Err(AegisError::new(ErrorCode::Conflict, "AegisWin is already running as administrator."));
    }
    // Stop the MCP server first so the elevated copy can bind the same port.
    engine.lock().await;
    match aegis_core::os::relaunch_elevated() {
        Ok(()) => {
            app.exit(0);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
            Err(AegisError::new(ErrorCode::AccessDenied, "The administrator prompt was cancelled. AegisWin is locked; unlock to continue."))
        }
        Err(e) => Err(AegisError::failed(format!("Could not restart as administrator: {e}"))),
    }
}

fn main() {
    let data_dir = data_dir();
    let engine = Engine::new(&data_dir, registry(), EngineOptions::default());
    let app = tauri::Builder::default()
        .manage(engine)
        .setup(move |app| {
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
