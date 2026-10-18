//! Application Tauri : commandes et événements par-dessus `patchprobe-core`/`patchprobe-platform`.

mod commands;
mod scan;
mod state;

use tauri::{Manager, RunEvent};

use state::AppState;

pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let paths = patchprobe_platform::paths::data_paths();
            // Les stores démarrent leur écrivain débouncé dans le runtime tokio de Tauri.
            let state = tauri::async_runtime::block_on(async move { AppState::load(paths) });
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::bootstrap,
            commands::detect_network,
            commands::start_scan,
            commands::cancel_scan,
            commands::ping_host,
            commands::open_url,
            commands::open_host,
            commands::open_ssh,
            commands::open_ftp,
            commands::get_name_trace,
            commands::diagnose_name,
            commands::run_nmap,
            commands::cancel_tool,
            commands::udp_scan,
            commands::snmp_walk,
            commands::traceroute,
            commands::wake_on_lan,
            commands::set_favorite,
            commands::set_note,
            commands::set_vendor_override,
            commands::save_settings,
            commands::apply_timing_preset,
            commands::apply_port_preset,
            commands::clear_resolution_cache,
            commands::list_history,
            commands::load_history,
            commands::delete_history,
            commands::diff_history,
            commands::list_site_profiles,
            commands::save_site_profile,
            commands::delete_site_profile,
            commands::create_site_profile_from_scan,
            commands::compare_site_profile,
            commands::export_scan,
            commands::export_file_name,
            commands::nmap_status,
        ])
        .build(tauri::generate_context!());

    let app = match app {
        Ok(app) => app,
        Err(error) => {
            eprintln!("PatchProbe n'a pas pu démarrer : {error}");
            std::process::exit(1);
        }
    };

    app.run(|handle, event| {
        // Fermeture : tout s'arrête (scan, sockets, processus nmap/traceroute) et les
        // écritures en attente sont faites avant de quitter.
        if let RunEvent::ExitRequested { .. } | RunEvent::Exit = event {
            if let Some(state) = handle.try_state::<AppState>() {
                state.cancel_all();
                tauri::async_runtime::block_on(state.flush_all());
            }
        }
    });
}
