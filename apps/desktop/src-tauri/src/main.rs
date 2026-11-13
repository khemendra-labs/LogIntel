// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
  #[cfg(target_os = "linux")]
  {
    // Prevent WebKitGTK 4.1 DMA-BUF / Mesa GPU hardware acceleration deadlocks and freezes on Linux (Wayland & X11)
    if std::env::var("WEBKIT_DISABLE_DMABUF_RENDERER").is_err() {
      unsafe {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
      }
    }
  }
  app_lib::run();
}
