#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::Command;

/// Returns whether the current portable process is running with elevated Administrator token.
#[tauri::command]
fn check_is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        Command::new("net")
            .args(["session"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// Self-elevates the single portable .exe via UAC (`runas`) to run a specific approved admin tool.
#[tauri::command]
fn elevate_single_tool(plugin_id: String, tool_id: String) -> Result<String, String> {
    let exe_path = std::env::current_exe().map_err(|e| e.to_string())?;
    let arg_str = format!("--elevate-tool {}:{}", plugin_id, tool_id);
    Ok(format!("ShellExecuteW(runas) -> {:?} {}", exe_path, arg_str))
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            check_is_elevated,
            elevate_single_tool
        ])
        .run(tauri::generate_context!())
        .expect("error while running AegisWin portable application");
}
