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
pub mod rule;

use std::sync::Arc;
use parking_lot::Mutex;
use crate::capture::CaptureEngine;
use crate::session::SessionTracker;
use crate::stats::StatsCollector;
use crate::rule::manager::RuleManager;

pub struct AppState {
    pub capture_engine: Arc<Mutex<CaptureEngine>>,
    pub session_tracker: Arc<Mutex<SessionTracker>>,
    pub stats_collector: Arc<Mutex<StatsCollector>>,
    pub rule_manager: Arc<Mutex<RuleManager>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            capture_engine: Arc::new(Mutex::new(CaptureEngine::new())),
            session_tracker: Arc::new(Mutex::new(SessionTracker::new())),
            stats_collector: Arc::new(Mutex::new(StatsCollector::new())),
            rule_manager: Arc::new(Mutex::new(RuleManager::new())),
        }
    }
}

pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .setup(|app| {
            let state = tauri::Manager::state::<AppState>(app);
            let _ = rule::commands::init_rule_manager(&app.handle(), &state);
            Ok(())
        })
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
            commands::set_packet_mark,
            commands::remove_packet_mark,
            commands::get_packet_mark,
            commands::get_all_marks,
            commands::get_tcp_timeline,
            commands::save_capture_template,
            commands::load_capture_templates,
            commands::delete_capture_template,
            commands::export_templates,
            commands::import_templates,
            rule::commands::get_rules,
            rule::commands::get_rule_groups,
            rule::commands::add_rule,
            rule::commands::update_rule,
            rule::commands::delete_rule,
            rule::commands::toggle_rule,
            rule::commands::add_rule_group,
            rule::commands::update_rule_group,
            rule::commands::delete_rule_group,
            rule::commands::parse_rule_expression,
            rule::commands::node_to_expression_string,
            rule::commands::validate_rule_regex,
            rule::commands::validate_rule_cidr,
            rule::commands::get_alerts,
            rule::commands::get_new_alerts,
            rule::commands::get_alert_count,
            rule::commands::clear_alerts,
            rule::commands::export_rules_to_file,
            rule::commands::import_rules_from_file,
            rule::commands::get_max_rules,
            rule::commands::get_max_alerts,
            rule::commands::compile_rule_regex,
            rule::commands::get_rule_versions,
            rule::commands::rollback_rule_version,
            rule::commands::check_rule_conflicts,
            rule::commands::get_rule_stats,
            rule::commands::batch_toggle_rules,
            rule::commands::batch_delete_rules,
            rule::commands::batch_move_rules_to_group,
            rule::commands::get_response_logs,
            rule::commands::get_response_logs_filtered,
            rule::commands::clear_response_logs,
            rule::commands::get_ban_entries,
            rule::commands::unban_ip,
            rule::commands::cleanup_expired_bans,
            rule::commands::clear_all_bans,
            rule::commands::get_response_config,
            rule::commands::save_response_config,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
