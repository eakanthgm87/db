// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Log panics to a file so we can diagnose window issues
    let log_path = std::env::current_exe()
        .unwrap_or_default()
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("veildb-crash.log");

    std::panic::set_hook(Box::new(move |info| {
        let msg = format!("PANIC: {info}\n");
        let _ = std::fs::write(&log_path, &msg);
        eprintln!("{msg}");
    }));

    veildb_bindings::run();
}
