pub mod models;
pub mod capture;
pub mod protocol;
pub mod session;
pub mod stream;
pub mod filter;
pub mod pcap_io;
pub mod stats;
pub mod tls;
pub mod commands;

use std::sync::Arc;
use parking_lot::Mutex;
use crate::capture::CaptureEngine;
use crate::session::SessionTracker;
use crate::stats::StatsCollector;

pub struct AppState {
    pub capture_engine: Arc<Mutex<CaptureEngine>>,
    pub session_tracker: Arc<Mutex<SessionTracker>>,
    pub stats_collector: Arc<Mutex<StatsCollector>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            capture_engine: Arc::new(Mutex::new(CaptureEngine::new())),
            session_tracker: Arc::new(Mutex::new(SessionTracker::new())),
            stats_collector: Arc::new(Mutex::new(StatsCollector::new())),
        }
    }
}

pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::list_interfaces,
            commands::start_capture,
            commands::stop_capture,
            commands::get_capture_status,
            commands::validate_bpf,
            commands::drain_new_packets,
            commands::get_packet_detail,
            commands::get_hex_dump,
            commands::apply_display_filter,
            commands::get_sessions,
            commands::trace_tcp_stream,
            commands::get_stats,
            commands::export_pcap,
            commands::import_pcap,
            commands::load_sslkeylog,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
