use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct EngineState {
    pub child: Arc<Mutex<Option<Child>>>,
}

/// Verify that the service listening on 127.0.0.1:41721 is genuinely the LogIntel engine
fn verify_engine_handshake() -> Result<bool, String> {
    let mut stream = match TcpStream::connect_timeout(
        &"127.0.0.1:41721".parse().unwrap(),
        Duration::from_millis(500),
    ) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    let _ = stream.set_read_timeout(Some(Duration::from_millis(1000)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));

    let req = "GET /api/v1/handshake HTTP/1.1\r\nHost: 127.0.0.1:41721\r\nConnection: close\r\n\r\n";
    if let Err(e) = stream.write_all(req.as_bytes()) {
        return Err(format!("Failed to write handshake request: {}", e));
    }

    let mut response = String::new();
    if let Err(e) = stream.read_to_string(&mut response) {
        return Err(format!("Failed to read handshake response: {}", e));
    }

    if response.contains("\"service\":\"logintel-engine\"") || response.contains("\"service\": \"logintel-engine\"") {
        Ok(true)
    } else {
        Err(format!(
            "Port 41721 is occupied by an alien service. Handshake rejected: {}",
            response.lines().next().unwrap_or("")
        ))
    }
}

fn spawn_engine_process() -> Option<Child> {
    let candidates = [
        PathBuf::from("/usr/lib/logintel/engine/.venv/bin/python"),
        PathBuf::from("/usr/lib/logintel/engine/venv/bin/python"),
        PathBuf::from("./apps/engine/.venv/bin/python"),
        PathBuf::from("../engine/.venv/bin/python"),
        PathBuf::from("../../apps/engine/.venv/bin/python"),
        PathBuf::from("/usr/bin/python3"),
    ];

    for python_bin in candidates.iter() {
        if python_bin.exists() {
            println!("Attempting to spawn LogIntel engine using {:?}", python_bin);
            let mut cmd = Command::new(python_bin);
            cmd.args(["-m", "logintel.main"]);

            // Set PYTHONPATH for local development if found
            let mut found_src = None;
            for candidate_src in [
                PathBuf::from("./apps/engine/src"),
                PathBuf::from("../engine/src"),
                PathBuf::from("../../apps/engine/src"),
                PathBuf::from("/usr/lib/logintel/engine/src"),
                PathBuf::from("/usr/lib/logintel/engine"),
            ] {
                if candidate_src.exists() {
                    found_src = Some(candidate_src);
                    break;
                }
            }

            if let Some(src) = found_src {
                cmd.env("PYTHONPATH", src);
            }

            match cmd.spawn() {
                Ok(child) => {
                    println!("Spawned LogIntel engine with PID {}", child.id());
                    return Some(child);
                }
                Err(err) => {
                    eprintln!("Failed to spawn engine with {:?}: {}", python_bin, err);
                }
            }
        }
    }

    eprintln!("Warning: LogIntel Python engine could not be spawned automatically.");
    None
}

fn ensure_engine_running() -> Option<Child> {
    match verify_engine_handshake() {
        Ok(true) => {
            println!("LogIntel engine is already running and authenticated via handshake on port 41721.");
            return None;
        }
        Err(err) => {
            eprintln!("CRITICAL PORT CONFLICT: {}", err);
            return None;
        }
        Ok(false) => {
            // Port is free; spawn engine
            spawn_engine_process()
        }
    }
}

#[tauri::command]
fn get_engine_token() -> Result<String, String> {
    let xdg_data = std::env::var("XDG_DATA_HOME").ok();
    let token_path = if let Some(data_dir) = xdg_data {
        PathBuf::from(data_dir).join("logintel/.engine_token")
    } else if let Some(home) = std::env::var("HOME").ok() {
        PathBuf::from(home).join(".local/share/logintel/.engine_token")
    } else {
        return Err("Cannot determine user data directory for engine token".into());
    };

    if !token_path.exists() {
        return Err(format!("Engine token file not found at {:?}", token_path));
    }

    std::fs::read_to_string(&token_path)
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("Failed to read engine token: {}", e))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let child_handle = Arc::new(Mutex::new(ensure_engine_running()));
    let child_for_exit = Arc::clone(&child_handle);
    let child_for_monitor = Arc::clone(&child_handle);
    let is_running = Arc::new(AtomicBool::new(true));
    let is_running_monitor = Arc::clone(&is_running);

    // Engine crash recovery monitor thread
    thread::spawn(move || {
        let mut restart_count = 0;
        const MAX_RESTARTS: usize = 3;

        while is_running_monitor.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(2));

            let mut lock = match child_for_monitor.lock() {
                Ok(l) => l,
                Err(_) => continue,
            };

            let needs_restart = if let Some(ref mut child) = *lock {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        eprintln!("LogIntel engine process exited unexpectedly with status: {:?}", status);
                        true
                    }
                    Ok(None) => false,
                    Err(e) => {
                        eprintln!("Error checking engine process status: {:?}", e);
                        false
                    }
                }
            } else {
                false
            };

            if needs_restart {
                if restart_count < MAX_RESTARTS {
                    restart_count += 1;
                    let backoff = Duration::from_secs(restart_count as u64);
                    eprintln!(
                        "Attempting bounded engine recovery restart ({}/{} in {:?})...",
                        restart_count, MAX_RESTARTS, backoff
                    );
                    thread::sleep(backoff);
                    *lock = spawn_engine_process();
                } else {
                    eprintln!("CRITICAL: Engine crashed repeatedly and exceeded maximum restart limit ({})", MAX_RESTARTS);
                    break;
                }
            }
        }
    });

    tauri::Builder::default()
        .manage(EngineState {
            child: Arc::clone(&child_handle),
        })
        .invoke_handler(tauri::generate_handler![get_engine_token])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(move |_app_handle, event| match event {
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit => {
                is_running.store(false, Ordering::Relaxed);
                if let Ok(mut lock) = child_for_exit.lock() {
                    if let Some(mut child) = lock.take() {
                        println!("Terminating managed LogIntel Python engine process...");
                        let _ = child.kill();
                    }
                }
            }
            _ => {}
        });
}
