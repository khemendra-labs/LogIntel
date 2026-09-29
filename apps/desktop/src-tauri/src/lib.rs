use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct EngineState {
    pub child: Arc<Mutex<Option<Child>>>,
}

fn is_engine_running() -> bool {
    let addr: SocketAddr = "127.0.0.1:41721".parse().unwrap();
    TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
}

fn try_spawn_engine() -> Option<Child> {
    if is_engine_running() {
        println!("LogIntel engine is already running on port 41721.");
        return None;
    }

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let child_handle = Arc::new(Mutex::new(try_spawn_engine()));
    let child_for_exit = Arc::clone(&child_handle);

    tauri::Builder::default()
        .manage(EngineState {
            child: Arc::clone(&child_handle),
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(move |_app_handle, event| match event {
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit => {
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
