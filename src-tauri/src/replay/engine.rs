use std::collections::HashMap;
use std::time::Duration;
use crate::models::PacketMetadata;
use crate::rule::engine::RuleEngine;
use crate::rule::models::{DetectionRule, ResponseLogEntry, ResponseResult};
use super::models::*;

pub fn inject_packets_to_engine(
    packets: Vec<PacketMetadata>,
    raw_data: Vec<Vec<u8>>,
    rule_engine: &mut RuleEngine,
) -> (Vec<RuleMatchRecord>, Vec<ResponseLogEntry>) {
    let mut rule_matches: HashMap<String, RuleMatchRecord> = HashMap::new();
    let mut response_logs: Vec<ResponseLogEntry> = Vec::new();

    rule_engine.clear_rate_counters();

    for (idx, meta) in packets.iter().enumerate() {
        let raw = raw_data.get(idx).map(|v| v.as_slice()).unwrap_or(&[]);

        rule_engine.record_packet_for_rate(meta);
        let matched_rules = rule_engine.evaluate_packet(meta, raw, None);

        for rule in matched_rules {
            let entry = rule_matches
                .entry(rule.id.clone())
                .or_insert_with(|| RuleMatchRecord {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    trigger_count: 0,
                    first_packet_no: meta.no,
                    first_timestamp_secs: meta.timestamp_secs,
                    first_timestamp_micros: meta.timestamp_micros,
                });
            entry.trigger_count += 1;

            if !rule.response_actions.is_empty() {
                for action in &rule.response_actions {
                    let log = generate_simulated_response_log(&rule, action, meta);
                    response_logs.push(log);
                }
            }
        }
    }

    let matches: Vec<RuleMatchRecord> = rule_matches.into_values().collect();
    (matches, response_logs)
}

pub fn replay_packets_with_timing<F>(
    packets: Vec<PacketMetadata>,
    raw_data: Vec<Vec<u8>>,
    rule_engine: &mut RuleEngine,
    speed_factor: f64,
    mut progress_cb: F,
) -> (Vec<RuleMatchRecord>, Vec<ResponseLogEntry>)
where
    F: FnMut(usize, usize),
{
    let mut rule_matches: HashMap<String, RuleMatchRecord> = HashMap::new();
    let mut response_logs: Vec<ResponseLogEntry> = Vec::new();
    let total = packets.len();

    rule_engine.clear_rate_counters();

    let mut prev_ts_micros: Option<u64> = None;

    for (idx, meta) in packets.iter().enumerate() {
        let curr_ts_micros = meta.timestamp_secs * 1_000_000 + meta.timestamp_micros as u64;

        if let Some(prev) = prev_ts_micros {
            if curr_ts_micros > prev {
                let diff_micros = curr_ts_micros - prev;
                let sleep_micros = (diff_micros as f64 / speed_factor) as u64;
                if sleep_micros > 0 {
                    std::thread::sleep(Duration::from_micros(sleep_micros));
                }
            }
        }
        prev_ts_micros = Some(curr_ts_micros);

        let raw = raw_data.get(idx).map(|v| v.as_slice()).unwrap_or(&[]);

        rule_engine.record_packet_for_rate(meta);
        let matched_rules = rule_engine.evaluate_packet(meta, raw, None);

        for rule in matched_rules {
            let entry = rule_matches
                .entry(rule.id.clone())
                .or_insert_with(|| RuleMatchRecord {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    trigger_count: 0,
                    first_packet_no: meta.no,
                    first_timestamp_secs: meta.timestamp_secs,
                    first_timestamp_micros: meta.timestamp_micros,
                });
            entry.trigger_count += 1;

            if !rule.response_actions.is_empty() {
                for action in &rule.response_actions {
                    let log = generate_simulated_response_log(&rule, action, meta);
                    response_logs.push(log);
                }
            }
        }

        progress_cb(idx + 1, total);
    }

    let matches: Vec<RuleMatchRecord> = rule_matches.into_values().collect();
    (matches, response_logs)
}

fn generate_simulated_response_log(
    rule: &DetectionRule,
    action: &crate::rule::models::ResponseAction,
    meta: &PacketMetadata,
) -> ResponseLogEntry {
    let action_type = match action {
        crate::rule::models::ResponseAction::Webhook { .. } => "webhook".to_string(),
        crate::rule::models::ResponseAction::IpBan { .. } => "ip_ban".to_string(),
        crate::rule::models::ResponseAction::ScriptExec { .. } => "script_exec".to_string(),
    };

    let detail = match action {
        crate::rule::models::ResponseAction::Webhook { url, .. } => {
            Some(format!("Simulated webhook to {}", url))
        }
        crate::rule::models::ResponseAction::IpBan { target, expire_minutes, .. } => {
            let ip = match target {
                crate::rule::models::BanTarget::Src => &meta.src_addr,
                crate::rule::models::BanTarget::Dst => &meta.dst_addr,
                crate::rule::models::BanTarget::Either => &meta.src_addr,
            };
            Some(format!("Simulated ban of {} for {} minutes", ip, expire_minutes))
        }
        crate::rule::models::ResponseAction::ScriptExec { path, .. } => {
            Some(format!("Simulated script execution: {}", path))
        }
    };

    ResponseLogEntry {
        id: format!("sim_{}_{}", rule.id, meta.no),
        trigger_time: meta.timestamp_secs,
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        action_type,
        result: ResponseResult::Success,
        duration_ms: 0,
        detail,
    }
}

pub fn replay_session_packets(
    session_id: &str,
    session_label: &str,
    packets: Vec<PacketMetadata>,
    raw_data: Vec<Vec<u8>>,
    rule_engine: &mut RuleEngine,
) -> ReplaySessionResult {
    let started_at = current_timestamp_secs();
    let total = packets.len() as u64;

    let (matched_rules, response_logs) = inject_packets_to_engine(packets.clone(), raw_data, rule_engine);

    let finished_at = current_timestamp_secs();

    ReplaySessionResult {
        session_id: session_id.to_string(),
        session_label: session_label.to_string(),
        total_packets: total,
        processed_packets: total,
        matched_rules,
        response_logs,
        started_at,
        finished_at,
    }
}

fn current_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn build_batch_summary(results: Vec<ReplaySessionResult>) -> ReplayBatchSummary {
    let mut total_packets = 0u64;
    let mut total_matched_rules = 0u64;
    let mut total_response_actions = 0u64;
    let mut sessions_with_hits = Vec::new();
    let mut sessions_without_hits = Vec::new();

    for r in &results {
        total_packets += r.total_packets;
        total_matched_rules += r.matched_rules.len() as u64;
        total_response_actions += r.response_logs.len() as u64;
        if r.matched_rules.is_empty() {
            sessions_without_hits.push(r.session_id.clone());
        } else {
            sessions_with_hits.push(r.session_id.clone());
        }
    }

    ReplayBatchSummary {
        session_count: results.len() as u64,
        total_packets,
        total_matched_rules,
        total_response_actions,
        sessions_with_hits,
        sessions_without_hits,
        per_session_results: results,
    }
}
