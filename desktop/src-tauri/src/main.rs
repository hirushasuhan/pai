// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{BufRead, BufReader, Read};
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

#[derive(serde::Serialize, Clone)]
struct BridgeConfig {
    port: u16,
    token: String,
}

struct AppState {
    bridge_child: Mutex<Option<Child>>,
    close_to_tray: Mutex<bool>,
    bridge_port: Mutex<u16>,
    bridge_token: Mutex<String>,
}

fn generate_token() -> String {
    #[cfg(windows)]
    {
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                h_algorithm: *mut std::ffi::c_void,
                pb_buffer: *mut u8,
                cb_buffer: u32,
                dw_flags: u32,
            ) -> i32;
        }
        let mut buf = [0u8; 32];
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                0x00000002, // BCRYPT_USE_SYSTEM_PREFERRED_RNG
            )
        };
        if status == 0 {
            return buf.iter().map(|b| format!("{:02x}", b)).collect();
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(123456789);
    format!("pai_tok_{:x}_{:x}", nanos, std::process::id())
}

#[tauri::command]
fn get_bridge_config(state: tauri::State<AppState>) -> Result<BridgeConfig, String> {
    let port = *state.bridge_port.lock().map_err(|e| e.to_string())?;
    let token = state.bridge_token.lock().map_err(|e| e.to_string())?.clone();
    Ok(BridgeConfig { port, token })
}

#[tauri::command]
fn set_close_behavior(to_tray: bool, state: tauri::State<AppState>) {
    if let Ok(mut lock) = state.close_to_tray.lock() {
        *lock = to_tray;
    }
}

#[tauri::command]
fn get_engine_status(state: tauri::State<AppState>) -> Result<serde_json::Value, String> {
    let mut ver = "1.5.0-beta.1".to_string();
    if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
        let v_file = Path::new(&local_app).join("Programs/PAI/VERSION");
        if let Ok(v) = std::fs::read_to_string(v_file) {
            let trimmed = v.trim().to_string();
            if !trimmed.is_empty() {
                ver = trimmed;
            }
        }
    }
    let port = *state.bridge_port.lock().map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "status": "ready",
        "version": ver,
        "framework": "Tauri 2.0 (Rust)",
        "loopback": format!("127.0.0.1:{}", port)
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

#[allow(dead_code)]
fn is_bridge_running_on_port(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", port).parse().unwrap(),
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
            let p4 = parent.join("../../desktop/bridge_server.py");
            if p4.is_file() {
                return Some(p4);
            }
        }
    }
    let candidates = [
        "desktop/bridge_server.py",
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
    if !local_app.is_empty() {
        let installed_root = Path::new(&local_app).join("Programs/PAI/bridge_server.py");
        if installed_root.is_file() {
            return Some(installed_root);
        }
        let installed_p = Path::new(&local_app).join("Programs/PAI/desktop/bridge_server.py");
        if installed_p.is_file() {
            return Some(installed_p);
        }
    }
    None
}

fn spawn_bridge_daemon() -> (Option<Child>, u16, String) {
    let token = generate_token();
    let py_bin = resolve_python_path();
    let script = match resolve_bridge_script() {
        Some(s) => s,
        None => return (None, 8765, token),
    };

    let mut cmd = Command::new(&py_bin);
    cmd.arg(&script);
    cmd.arg("--port");
    cmd.arg("0");
    cmd.env("PAI_BRIDGE_TOKEN", &token);

    if let Some(script_dir) = script.parent() {
        cmd.current_dir(script_dir);
    }

    #[cfg(windows)]
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    cmd.stdout(std::process::Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return (None, 8765, token),
    };

    let mut actual_port = 8765u16;

    if let Some(stdout) = child.stdout.take() {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        for _ in 0..30 {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if let Some(idx) = line.find("PAI_BRIDGE_READY") {
                        let rest = &line[idx + "PAI_BRIDGE_READY".len()..];
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(rest.trim()) {
                            if let Some(p) = val.get("port").and_then(|v| v.as_u64()) {
                                actual_port = p as u16;
                                break;
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }

        std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let mut r = reader.into_inner();
            while let Ok(n) = r.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
        });
    }

    (Some(child), actual_port, token)
}

fn main() {
    let (bridge_proc, port, token) = spawn_bridge_daemon();

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
            bridge_port: Mutex::new(port),
            bridge_token: Mutex::new(token),
        })
        .invoke_handler(tauri::generate_handler![
            get_engine_status,
            get_bridge_config,
            app_window_minimize,
            app_window_unminimize,
            app_window_toggle_maximize,
            app_window_close,
            set_close_behavior,
            app_window_exit
        ])
        .setup(|app| {
            let status_i = MenuItemBuilder::with_id("status", "PAI Studio v1.5.0-beta.1 (Active)")
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
