// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::{Child, Command};
use std::sync::Mutex;
use tauri::Manager;

struct AppState {
    bridge_child: Mutex<Option<Child>>,
}

#[tauri::command]
fn get_engine_status() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "status": "ready",
        "version": "1.1.0",
        "framework": "Tauri 2.0 (Rust)",
        "loopback": "127.0.0.1:8765"
    }))
}

fn spawn_bridge_daemon() -> Option<Child> {
    // Attempt to spawn Python bridge server daemon in background
    let py = if cfg!(windows) { "python.exe" } else { "python3" };
    Command::new(py)
        .arg("desktop/bridge_server.py")
        .spawn()
        .ok()
}

fn main() {
    let bridge_proc = spawn_bridge_daemon();

    tauri::Builder::default()
        .manage(AppState {
            bridge_child: Mutex::new(bridge_proc),
        })
        .invoke_handler(tauri::generate_handler![get_engine_status])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                // Terminate background bridge server when main window is closed
                let state = window.state::<AppState>();
                if let Ok(mut lock) = state.bridge_child.lock() {
                    if let Some(mut child) = lock.take() {
                        let _ = child.kill();
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running PAI Studio Tauri application");
}
