use std::sync::Arc;
use parking_lot::Mutex;
use tauri::{State, AppHandle, Manager};
use serde::Serialize;
use crate::AppState;
use crate::replay::patterns::AttackPatternManager;
use super::models::*;
use super::engine::{build_batch_summary, inject_packets_to_engine, replay_packets_with_timing};
use super::generator::generate_traffic;

#[derive(Debug, Clone, Serialize)]
pub struct ReplayProgressEvent {
    pub session_index: u32,
    pub total_sessions: u32,
    pub current_packet: u32,
    pub total_packets: u32,
    pub session_id: String,
    pub session_label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectivenessReportProgressEvent {
    pub current_pattern: u32,
    pub total_patterns: u32,
    pub pattern_id: String,
    pub pattern_name: String,
}

fn current_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tauri::command]
pub fn init_replay_module(
    app: tauri::AppHandle,
    pattern_manager: Arc<Mutex<AttackPatternManager>>,
) -> Result<(), String> {
    let app_dir = app
        .path_resolver()
        .app_data_dir()
        .ok_or_else(|| "Failed to get app data directory".to_string())?;

    std::fs::create_dir_all(&app_dir).map_err(|e| e.to_string())?;
    let path = app_dir.join("attack_patterns.json");

    let mut pm = pattern_manager.lock();
    pm.set_file_path(path);
    pm.load_from_disk()?;
    Ok(())
}

#[tauri::command]
pub fn get_session_packets_for_replay(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<(Vec<crate::models::PacketMetadata>, Vec<Vec<u8>>), String> {
    let tracker = state.session_tracker.lock();
    let packet_nos = tracker
        .get_session_packet_nos(&session_id)
        .ok_or_else(|| format!("Session '{}' not found", session_id))?;
    drop(tracker);

    let engine = state.capture_engine.lock();
    let mut packets = Vec::new();
    let mut raw_data = Vec::new();

    for no in packet_nos {
        if let Some(meta) = engine.get_metadata(no) {
            if let Some(raw) = engine.get_raw_data(no) {
                packets.push(meta);
                raw_data.push(raw);
            }
        }
    }

    Ok((packets, raw_data))
}

#[tauri::command]
pub fn replay_sessions(
    app: AppHandle,
    state: State<'_, AppState>,
    session_ids: Vec<String>,
) -> Result<ReplayBatchSummary, String> {
    let mut results = Vec::new();
    let total_sessions = session_ids.len() as u32;

    let rule_engine_clone = {
        let mut rm = state.rule_manager.lock();
        rm.clear_rate_counters();
        rm.get_rule_engine_clone()
    };

    let mut rule_engine = rule_engine_clone.lock();

    for (sess_idx, sid) in session_ids.iter().enumerate() {
        let (packets, raw_data) = get_session_packets_for_replay_inner(&state, sid)?;
        let tracker = state.session_tracker.lock();
        let session_info = tracker
            .get_sessions()
            .into_iter()
            .find(|s| s.id == *sid);
        drop(tracker);

        let label = match &session_info {
            Some(s) => format!("{}:{} -> {}:{}", s.src_addr, s.src_port, s.dst_addr, s.dst_port),
            None => sid.clone(),
        };

        let total_packets = packets.len();
        let started_at = current_timestamp_secs();

        let sid_for_cb = sid.clone();
        let label_for_cb = label.clone();
        let app_clone = app.clone();
        let sess_idx_u32 = sess_idx as u32;

        let (matched_rules, response_logs) = replay_packets_with_timing(
            packets.clone(),
            raw_data,
            &mut rule_engine,
            1.0,
            move |current, total| {
                let event = ReplayProgressEvent {
                    session_index: sess_idx_u32,
                    total_sessions,
                    current_packet: current as u32,
                    total_packets: total as u32,
                    session_id: sid_for_cb.clone(),
                    session_label: label_for_cb.clone(),
                };
                let _ = app_clone.emit_all("replay_progress", &event);
            },
        );

        let finished_at = current_timestamp_secs();

        let result = ReplaySessionResult {
            session_id: sid.clone(),
            session_label: label,
            total_packets: total_packets as u64,
            processed_packets: total_packets as u64,
            matched_rules,
            response_logs,
            started_at,
            finished_at,
        };
        results.push(result);
    }

    Ok(build_batch_summary(results))
}

fn get_session_packets_for_replay_inner(
    state: &State<'_, AppState>,
    session_id: &str,
) -> Result<(Vec<crate::models::PacketMetadata>, Vec<Vec<u8>>), String> {
    let tracker = state.session_tracker.lock();
    let packet_nos = tracker
        .get_session_packet_nos(session_id)
        .ok_or_else(|| format!("Session '{}' not found", session_id))?;
    drop(tracker);

    let engine = state.capture_engine.lock();
    let mut packets = Vec::new();
    let mut raw_data = Vec::new();

    for no in packet_nos {
        if let Some(meta) = engine.get_metadata(no) {
            if let Some(raw) = engine.get_raw_data(no) {
                packets.push(meta);
                raw_data.push(raw);
            }
        }
    }

    Ok((packets, raw_data))
}

#[tauri::command]
pub fn get_attack_patterns(
    state: State<'_, AppState>,
    category: Option<String>,
) -> Result<Vec<AttackPattern>, String> {
    let pm = state.replay_state.pattern_manager.lock();
    if let Some(cat_str) = category {
        let cat = match cat_str.to_lowercase().as_str() {
            "port_scan" | "portscan" => AttackCategory::PortScan,
            "syn_flood" | "synflood" => AttackCategory::SynFlood,
            "dns_amplification" | "dnsamp" => AttackCategory::DnsAmplification,
            "brute_force" | "bruteforce" => AttackCategory::BruteForce,
            "arp_spoof" | "arpspoof" => AttackCategory::ArpSpoof,
            "http_flood" | "httpflood" => AttackCategory::HttpFlood,
            "udp_flood" | "udpflood" => AttackCategory::UdpFlood,
            "icmp_flood" | "icmpflood" => AttackCategory::IcmpFlood,
            "slow_loris" | "slowloris" => AttackCategory::SlowLoris,
            _ => AttackCategory::Custom,
        };
        Ok(pm.get_patterns_by_category(&cat))
    } else {
        Ok(pm.get_all_patterns())
    }
}

#[tauri::command]
pub fn add_attack_pattern(
    state: State<'_, AppState>,
    pattern: AttackPattern,
) -> Result<(), String> {
    let mut pm = state.replay_state.pattern_manager.lock();
    pm.add_custom_pattern(pattern)
}

#[tauri::command]
pub fn update_attack_pattern(
    state: State<'_, AppState>,
    pattern: AttackPattern,
) -> Result<(), String> {
    let mut pm = state.replay_state.pattern_manager.lock();
    pm.update_custom_pattern(pattern)
}

#[tauri::command]
pub fn delete_attack_pattern(
    state: State<'_, AppState>,
    pattern_id: String,
) -> Result<(), String> {
    let mut pm = state.replay_state.pattern_manager.lock();
    pm.delete_custom_pattern(&pattern_id)
}

#[tauri::command]
pub fn generate_simulated_traffic(
    state: State<'_, AppState>,
    pattern_id: String,
    target_ip: Option<String>,
) -> Result<(Vec<crate::models::PacketMetadata>, Vec<Vec<u8>>), String> {
    let pm = state.replay_state.pattern_manager.lock();
    let pattern = pm
        .get_pattern(&pattern_id)
        .ok_or_else(|| format!("Attack pattern '{}' not found", pattern_id))?;
    drop(pm);

    let traffic = generate_traffic(&pattern, target_ip);
    Ok((traffic.packets, traffic.raw_data))
}

#[tauri::command]
pub fn run_pattern_against_engine(
    app: AppHandle,
    state: State<'_, AppState>,
    pattern_id: String,
    target_ip: Option<String>,
) -> Result<ReplaySessionResult, String> {
    let pm = state.replay_state.pattern_manager.lock();
    let pattern = pm
        .get_pattern(&pattern_id)
        .ok_or_else(|| format!("Attack pattern '{}' not found", pattern_id))?;
    drop(pm);

    let traffic = generate_traffic(&pattern, target_ip.clone());
    let label = format!("{} ({})", pattern.name, pattern.category.as_str());

    let rule_engine_clone = {
        let mut rm = state.rule_manager.lock();
        rm.clear_rate_counters();
        rm.get_rule_engine_clone()
    };
    let mut rule_engine = rule_engine_clone.lock();

    let total_packets = traffic.packets.len();
    let started_at = current_timestamp_secs();

    let pattern_id_clone = pattern_id.clone();
    let label_clone = label.clone();
    let app_clone = app.clone();

    let (matched_rules, response_logs) = replay_packets_with_timing(
        traffic.packets.clone(),
        traffic.raw_data,
        &mut rule_engine,
        1.0,
        move |current, total| {
            let event = ReplayProgressEvent {
                session_index: 0,
                total_sessions: 1,
                current_packet: current as u32,
                total_packets: total as u32,
                session_id: pattern_id_clone.clone(),
                session_label: label_clone.clone(),
            };
            let _ = app_clone.emit_all("simulation_progress", &event);
        },
    );

    let finished_at = current_timestamp_secs();

    Ok(ReplaySessionResult {
        session_id: pattern_id,
        session_label: label,
        total_packets: total_packets as u64,
        processed_packets: total_packets as u64,
        matched_rules,
        response_logs,
        started_at,
        finished_at,
    })
}

#[tauri::command]
pub fn generate_rule_effectiveness_report(
    app: AppHandle,
    state: State<'_, AppState>,
    pattern_ids: Vec<String>,
    target_ip: Option<String>,
) -> Result<RuleEffectivenessReport, String> {
    let mut items = Vec::new();
    let mut detected = 0u64;
    let mut undetected = 0u64;
    let total_patterns = pattern_ids.len() as u32;

    for (idx, pid) in pattern_ids.iter().enumerate() {
        let pm = state.replay_state.pattern_manager.lock();
        let pattern = match pm.get_pattern(pid) {
            Some(p) => p,
            None => continue,
        };
        drop(pm);

        let event = EffectivenessReportProgressEvent {
            current_pattern: idx as u32,
            total_patterns,
            pattern_id: pattern.id.clone(),
            pattern_name: pattern.name.clone(),
        };
        let _ = app.emit_all("effectiveness_report_progress", &event);

        let traffic = generate_traffic(&pattern, target_ip.clone());

        let rule_engine_clone = {
            let mut rm = state.rule_manager.lock();
            rm.clear_rate_counters();
            rm.get_rule_engine_clone()
        };
        let mut rule_engine = rule_engine_clone.lock();

        let (matched_rules, response_logs) = inject_packets_to_engine(
            traffic.packets.clone(),
            traffic.raw_data,
            &mut rule_engine,
        );

        let is_detected = !matched_rules.is_empty();
        if is_detected {
            detected += 1;
        } else {
            undetected += 1;
        }

        let matched_names: Vec<String> = matched_rules.iter().map(|r| r.rule_name.clone()).collect();
        let resp_actions: Vec<String> = response_logs.iter().map(|l| l.action_type.clone()).collect();

        items.push(RuleEffectivenessItem {
            pattern_id: pattern.id.clone(),
            pattern_name: pattern.name.clone(),
            pattern_category: pattern.category.as_str().to_string(),
            is_detected,
            matched_rule_names: matched_names,
            response_triggered: !response_logs.is_empty(),
            response_actions: resp_actions,
            total_packets: traffic.packets.len() as u64,
        });
    }

    let total = items.len() as u64;
    let detection_rate = if total > 0 {
        detected as f64 / total as f64
    } else {
        0.0
    };

    Ok(RuleEffectivenessReport {
        generated_at: current_timestamp_secs(),
        total_patterns: total,
        detected_count: detected,
        undetected_count: undetected,
        detection_rate,
        items,
    })
}

#[tauri::command]
pub fn export_replay_result_json(
    result: ReplaySessionResult,
    path: String,
) -> Result<(), String> {
    let content = serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?;
    std::fs::write(&path, content).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn export_batch_summary_json(
    summary: ReplayBatchSummary,
    path: String,
) -> Result<(), String> {
    let content = serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?;
    std::fs::write(&path, content).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn export_effectiveness_report_json(
    report: RuleEffectivenessReport,
    path: String,
) -> Result<(), String> {
    let content = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    std::fs::write(&path, content).map_err(|e| e.to_string())
}
