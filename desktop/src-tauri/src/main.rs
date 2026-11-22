// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::Duration;
use tauri::Manager;
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

struct AppState {
    bridge_child: Mutex<Option<Child>>,
    close_to_tray: Mutex<bool>,
}

#[tauri::command]
fn set_close_behavior(to_tray: bool, state: tauri::State<AppState>) {
    if let Ok(mut lock) = state.close_to_tray.lock() {
        *lock = to_tray;
    }
}

#[tauri::command]
fn get_engine_status() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "status": "ready",
        "version": "1.3.0",
        "framework": "Tauri 2.0 (Rust)",
        "loopback": "127.0.0.1:8765"
    }))
}

#[tauri::command]
fn app_window_minimize(window: tauri::Window) {
    let _ = window.minimize();
}

#[tauri::command]
fn app_window_unminimize(window: tauri::Window) {
    let _ = window.show();
    let _ = window.unminimize();
    let _ = window.set_focus();
}

#[tauri::command]
fn app_window_toggle_maximize(window: tauri::Window) {
    if let Ok(is_max) = window.is_maximized() {
        if is_max {
            let _ = window.unmaximize();
        } else {
            let _ = window.maximize();
        }
    }
}

#[tauri::command]
fn app_window_close(window: tauri::Window, state: tauri::State<AppState>) {
    let to_tray = state.close_to_tray.lock().map(|l| *l).unwrap_or(true);
    if to_tray {
        let _ = window.hide();
    } else {
        if let Ok(mut lock) = state.bridge_child.lock() {
            if let Some(mut child) = lock.take() {
                let _ = child.kill();
            }
        }
        std::process::exit(0);
    }
}

#[tauri::command]
fn app_window_exit(state: tauri::State<AppState>) {
    if let Ok(mut lock) = state.bridge_child.lock() {
        if let Some(mut child) = lock.take() {
            let _ = child.kill();
        }
    }
    std::process::exit(0);
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
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .manage(AppState {
            bridge_child: Mutex::new(bridge_proc),
            close_to_tray: Mutex::new(true),
        })
        .invoke_handler(tauri::generate_handler![
            get_engine_status,
            app_window_minimize,
            app_window_unminimize,
            app_window_toggle_maximize,
            app_window_close,
            set_close_behavior,
            app_window_exit
        ])
        .setup(|app| {
            let status_i = MenuItemBuilder::with_id("status", "PAI Studio v1.3.0 (Active)")
                .enabled(false)
                .build(app)?;
            let show_i = MenuItemBuilder::with_id("show", "Open PAI Studio").build(app)?;
            let quit_i = MenuItemBuilder::with_id("quit", "Quit PAI Studio").build(app)?;

            let menu = MenuBuilder::new(app)
                .items(&[&status_i, &show_i, &quit_i])
                .build()?;

            let mut builder = TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .tooltip("PAI Studio - Personal Agentic AI (Running in Background)")
                .on_menu_event(|app, event| {
                    match event.id.as_ref() {
                        "show" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
                            }
                        }
                        "quit" => {
                            let state = app.state::<AppState>();
                            if let Ok(mut lock) = state.bridge_child.lock() {
                                if let Some(mut child) = lock.take() {
                                    let _ = child.kill();
                                }
                            }
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                });

            let tray_icon = app
                .default_window_icon()
                .cloned()
                .or_else(|| tauri::image::Image::from_app_icon_resource(32).ok())
                .unwrap_or_else(|| {
                    let mut rgba = Vec::with_capacity(16 * 16 * 4);
                    for _ in 0..(16 * 16) {
                        rgba.extend_from_slice(&[0x06, 0xb6, 0xd4, 0xff]);
                    }
                    tauri::image::Image::new_owned(rgba, 16, 16)
                });

            builder = builder.icon(tray_icon);

            if let Err(err) = builder.build(app) {
                eprintln!("[Tauri] Warning: Failed to build system tray icon: {err}");
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            match event {
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    let state = window.state::<AppState>();
                    let to_tray = {
                        let lock_res = state.close_to_tray.lock();
                        lock_res.map(|l| *l).unwrap_or(true)
                    };
                    if to_tray {
                        api.prevent_close();
                        let _ = window.hide();
                    } else {
                        let lock_res = state.bridge_child.lock();
                        if let Ok(mut lock) = lock_res {
                            if let Some(mut child) = lock.take() {
                                let _ = child.kill();
                            }
                        }
                    }
                }
                tauri::WindowEvent::Destroyed => {
                    let state = window.state::<AppState>();
                    let lock_res = state.bridge_child.lock();
                    if let Ok(mut lock) = lock_res {
                        if let Some(mut child) = lock.take() {
                            let _ = child.kill();
                        }
                    }
                }
                _ => {}
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running PAI Studio Tauri application");
}
