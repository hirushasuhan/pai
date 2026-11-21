// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::Duration;
use tauri::Manager;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

struct AppState {
    bridge_child: Mutex<Option<Child>>,
}

#[tauri::command]
fn get_engine_status() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "status": "ready",
        "version": "1.2.0",
        "framework": "Tauri 2.0 (Rust)",
        "loopback": "127.0.0.1:8765"
    }))
}

fn is_bridge_running() -> bool {
    TcpStream::connect_timeout(
        &"127.0.0.1:8765".parse().unwrap(),
        Duration::from_millis(400),
    )
    .is_ok()
}

fn resolve_python_path() -> PathBuf {
    let local_app = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let pai_pyw = Path::new(&local_app).join("Programs/PAI/python/pythonw.exe");
    if pai_pyw.is_file() {
        return pai_pyw;
    }
    let pai_py = Path::new(&local_app).join("Programs/PAI/python/python.exe");
    if pai_py.is_file() {
        return pai_py;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let p1 = parent.join("python/pythonw.exe");
            if p1.is_file() {
                return p1;
            }
            let p2 = parent.join("../python/pythonw.exe");
            if p2.is_file() {
                return p2;
            }
        }
    }
    PathBuf::from(if cfg!(windows) { "pythonw.exe" } else { "python3" })
}

fn resolve_bridge_script() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let p0 = parent.join("bridge_server.py");
            if p0.is_file() {
                return Some(p0);
            }
            let p1 = parent.join("desktop/bridge_server.py");
            if p1.is_file() {
                return Some(p1);
            }
            let p2 = parent.join("../../../desktop/bridge_server.py");
            if p2.is_file() {
                return Some(p2);
            }
            let p3 = parent.join("../../../../desktop/bridge_server.py");
            if p3.is_file() {
                return Some(p3);
            }
            let p4 = parent.join("../../../research/desktop/bridge_server.py");
            if p4.is_file() {
                return Some(p4);
            }
            let p5 = parent.join("../../desktop/bridge_server.py");
            if p5.is_file() {
                return Some(p5);
            }
        }
    }
    let candidates = [
        "desktop/bridge_server.py",
        "research/desktop/bridge_server.py",
        "../desktop/bridge_server.py",
        "../../desktop/bridge_server.py",
        "bridge_server.py",
    ];
    for c in &candidates {
        let p = Path::new(c);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    let local_app = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let installed_root = Path::new(&local_app).join("Programs/PAI/bridge_server.py");
    if installed_root.is_file() {
        return Some(installed_root);
    }
    let installed_p = Path::new(&local_app).join("Programs/PAI/desktop/bridge_server.py");
    if installed_p.is_file() {
        return Some(installed_p);
    }
    let installed_r = Path::new(&local_app).join("Programs/PAI/research/desktop/bridge_server.py");
    if installed_r.is_file() {
        return Some(installed_r);
    }
    None
}

fn spawn_bridge_daemon() -> Option<Child> {
    if is_bridge_running() {
        return None;
    }

    let py_bin = resolve_python_path();
    let script = resolve_bridge_script()?;

    let mut cmd = Command::new(&py_bin);
    cmd.arg(&script);

    #[cfg(windows)]
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW

    let child = cmd.spawn().ok();

    // Wait up to 3 seconds for bridge to respond
    for _ in 0..15 {
        std::thread::sleep(Duration::from_millis(200));
        if is_bridge_running() {
            break;
        }
    }

    child
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
                let state = window.state::<AppState>();
                let lock_res = state.bridge_child.lock();
                if let Ok(mut lock) = lock_res {
                    if let Some(mut child) = lock.take() {
                        let _ = child.kill();
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running PAI Studio Tauri application");
}
