use std::sync::Arc;
use std::collections::VecDeque;
use std::collections::HashMap;
use parking_lot::Mutex;
use crossbeam_channel::{Sender, Receiver, bounded};
use crate::models::{PacketMetadata, RawPacket, RulePacketEvent};
use super::models::*;
use super::engine::RuleEngine;
use super::actions::AlertActionExecutor;
use super::persistence;
use super::conflict;
use super::response::ResponseExecutor;
use super::ban_list::BanListManager;

pub const MAX_ALERTS: usize = 50_000;
const MAX_VERSIONS: usize = 20;

pub struct RuleManager {
    rules: Vec<DetectionRule>,
    groups: Vec<RuleGroup>,
    alerts: VecDeque<AlertRecord>,
    rule_stats: HashMap<String, RuleStats>,
    shared_stats: Arc<Mutex<HashMap<String, RuleStats>>>,
    rule_engine: Arc<Mutex<RuleEngine>>,
    action_executor: Arc<Mutex<AlertActionExecutor>>,
    response_executor: Arc<Mutex<ResponseExecutor>>,
    ban_list: Arc<Mutex<BanListManager>>,
    response_config: Arc<Mutex<ResponseConfig>>,
    app_data_dir: Option<std::path::PathBuf>,
    tx: Option<Sender<RulePacketEvent>>,
    rx: Option<Receiver<RulePacketEvent>>,
    worker_handle: Option<std::thread::JoinHandle<()>>,
    stop_flag: Arc<std::sync::atomic::AtomicBool>,
    alert_tx: Option<crossbeam_channel::Sender<AlertRecord>>,
    alert_rx: Arc<Mutex<Option<crossbeam_channel::Receiver<AlertRecord>>>>,
}

impl RuleManager {
    pub fn new() -> Self {
        let (tx, rx) = bounded(100000);
        let (alert_tx, alert_rx) = bounded(5000);

        let ban_list = Arc::new(Mutex::new(BanListManager::new()));
        let response_config = Arc::new(Mutex::new(ResponseConfig::default()));
        let response_executor = Arc::new(Mutex::new(ResponseExecutor::new(ban_list.clone(), response_config.clone(), None)));

        Self {
            rules: Vec::new(),
            groups: Vec::new(),
            alerts: VecDeque::new(),
            rule_stats: HashMap::new(),
            shared_stats: Arc::new(Mutex::new(HashMap::new())),
            rule_engine: Arc::new(Mutex::new(RuleEngine::new())),
            action_executor: Arc::new(Mutex::new(AlertActionExecutor::new())),
            response_executor,
            ban_list,
            response_config,
            app_data_dir: None,
            tx: Some(tx),
            rx: Some(rx),
            worker_handle: None,
            stop_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            alert_tx: Some(alert_tx),
            alert_rx: Arc::new(Mutex::new(Some(alert_rx))),
        }
    }

    pub fn set_app_data_dir(&mut self, path: std::path::PathBuf) {
        self.app_data_dir = Some(path.clone());
        self.response_executor = Arc::new(Mutex::new(ResponseExecutor::new(
            self.ban_list.clone(),
            self.response_config.clone(),
            Some(path),
        )));
    }

    pub fn set_app_handle(&mut self, handle: tauri::AppHandle) {
        let mut executor = self.action_executor.lock();
        executor.set_app_handle(handle);
    }

    pub fn set_capture_engine(&mut self, engine: Arc<Mutex<crate::capture::CaptureEngine>>) {
        let mut executor = self.action_executor.lock();
        executor.set_mark_engine(engine);
    }

    pub fn load_from_disk(&mut self) -> Result<(), String> {
        if let Some(ref dir) = self.app_data_dir {
            let rules_file = persistence::load_rules(dir)?;
            self.groups = rules_file.groups;
            self.rules = rules_file.rules;
            self.rule_stats.clear();
            for stat in rules_file.rule_stats {
                self.rule_stats.insert(stat.rule_id.clone(), stat);
            }
            for rule in &self.rules {
                if !self.rule_stats.contains_key(&rule.id) {
                    self.rule_stats.insert(rule.id.clone(), RuleStats {
                        rule_id: rule.id.clone(),
                        ..Default::default()
                    });
                }
            }

            let config_path = dir.join("response_config.json");
            if config_path.exists() {
                let content = std::fs::read_to_string(&config_path).map_err(|e| e.to_string())?;
                let config: ResponseConfig = serde_json::from_str(&content).unwrap_or_default();
                *self.response_config.lock() = config;
            }

            let config = self.response_config.lock();
            let ban_path = dir.join(&config.ban_list_path);
            drop(config);
            self.ban_list.lock().set_file_path(ban_path);

            self.refresh_engine();
        }
        Ok(())
    }

    pub fn save_to_disk(&self) -> Result<(), String> {
        if let Some(ref dir) = self.app_data_dir {
            let shared = self.shared_stats.lock();
            let mut stats_map: HashMap<String, RuleStats> = self.rule_stats.clone();
            for (id, shared_stat) in shared.iter() {
                if let Some(local) = stats_map.get_mut(id) {
                    local.total_triggers = local.total_triggers.max(shared_stat.total_triggers);
                    local.triggers_last_24h = shared_stat.triggers_last_24h;
                    local.last_trigger_time = shared_stat.last_trigger_time.or(local.last_trigger_time);
                } else {
                    stats_map.insert(id.clone(), shared_stat.clone());
                }
            }
            drop(shared);
            let stats_vec: Vec<RuleStats> = stats_map.into_values().collect();
            let rules_file = RulesFile {
                version: "1.0".to_string(),
                groups: self.groups.clone(),
                rules: self.rules.clone(),
                rule_stats: stats_vec,
            };
            persistence::save_rules(dir, &rules_file)?;
        }
        Ok(())
    }

    fn refresh_engine(&mut self) {
        let mut enabled_rules: Vec<DetectionRule> = self.rules
            .iter()
            .filter(|r| r.enabled)
            .cloned()
            .collect();

        for rule in &mut enabled_rules {
            let _ = super::engine::compile_regex_in_rule(rule);
        }

        enabled_rules.sort_by_key(|r| r.priority.order());

        let mut engine = self.rule_engine.lock();
        engine.set_rules(enabled_rules);
    }

    pub fn get_rules(&self) -> Vec<DetectionRule> {
        self.rules.clone()
    }

    pub fn get_groups(&self) -> Vec<RuleGroup> {
        self.groups.clone()
    }

    pub fn get_alerts(&self) -> Vec<AlertRecord> {
        self.alerts.iter().rev().cloned().collect()
    }

    pub fn get_alert_count(&self) -> usize {
        self.alerts.len()
    }

    fn create_version_snapshot(rule: &DetectionRule) -> RuleVersion {
        let summary = generate_condition_summary(&rule.condition);
        RuleVersion {
            version: rule.current_version,
            condition: strip_compiled_regex(rule.condition.clone()),
            expression: rule.expression.clone(),
            actions: rule.actions.clone(),
            saved_at: current_timestamp_secs(),
            summary,
        }
    }

    pub fn add_rule(&mut self, mut rule: DetectionRule) -> Result<(), String> {
        if self.rules.len() >= persistence::max_rules() {
            return Err(format!(
                "规则数量已达上限({})，请删除旧规则",
                persistence::max_rules()
            ));
        }

        if self.rules.iter().any(|r| r.id == rule.id) {
            return Err("规则ID已存在".to_string());
        }

        let _ = super::engine::compile_regex_in_rule(&mut rule)?;

        rule.current_version = 1;
        let version = Self::create_version_snapshot(&rule);
        rule.versions = vec![version];

        self.rule_stats.insert(rule.id.clone(), RuleStats {
            rule_id: rule.id.clone(),
            ..Default::default()
        });

        self.rules.push(rule);
        self.refresh_engine();
        self.save_to_disk()?;
        Ok(())
    }

    pub fn update_rule(&mut self, mut rule: DetectionRule) -> Result<(), String> {
        let _ = super::engine::compile_regex_in_rule(&mut rule)?;

        if let Some(existing) = self.rules.iter_mut().find(|r| r.id == rule.id) {
            let old_version = Self::create_version_snapshot(existing);

            rule.current_version = existing.current_version + 1;
            let mut versions = existing.versions.clone();
            versions.push(old_version);
            if versions.len() > MAX_VERSIONS {
                let drain_count = versions.len() - MAX_VERSIONS;
                versions.drain(..drain_count);
            }
            rule.versions = versions;

            *existing = rule;
            self.refresh_engine();
            self.save_to_disk()?;
            Ok(())
        } else {
            Err("规则不存在".to_string())
        }
    }

    pub fn delete_rule(&mut self, rule_id: &str) -> Result<(), String> {
        self.rules.retain(|r| r.id != rule_id);
        self.rule_stats.remove(rule_id);
        self.refresh_engine();
        self.save_to_disk()?;
        Ok(())
    }

    pub fn toggle_rule(&mut self, rule_id: &str, enabled: bool) -> Result<(), String> {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == rule_id) {
            rule.enabled = enabled;
            rule.updated_at = current_timestamp_secs();
            self.refresh_engine();
            self.save_to_disk()?;
            Ok(())
        } else {
            Err("规则不存在".to_string())
        }
    }

    pub fn get_rule_versions(&self, rule_id: &str) -> Option<Vec<RuleVersion>> {
        self.rules.iter().find(|r| r.id == rule_id).map(|r| r.versions.clone())
    }

    pub fn rollback_rule(&mut self, rule_id: &str, target_version: u32) -> Result<(), String> {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == rule_id) {
            let target = rule.versions.iter().find(|v| v.version == target_version);
            let target = match target {
                Some(v) => v.clone(),
                None => return Err("目标版本不存在".to_string()),
            };

            let old_snapshot = Self::create_version_snapshot(rule);
            rule.versions.push(old_snapshot);
            if rule.versions.len() > MAX_VERSIONS {
                let drain_count = rule.versions.len() - MAX_VERSIONS;
                rule.versions.drain(..drain_count);
            }

            rule.current_version += 1;
            rule.condition = target.condition.clone();
            rule.expression = target.expression.clone();
            rule.actions = target.actions.clone();
            rule.updated_at = current_timestamp_secs();

            let _ = super::engine::compile_regex_in_rule(rule);

            self.refresh_engine();
            self.save_to_disk()?;
            Ok(())
        } else {
            Err("规则不存在".to_string())
        }
    }

    pub fn check_conflicts(&self, rule: &DetectionRule) -> Vec<RuleConflict> {
        let mut conflicts = Vec::new();
        for existing in &self.rules {
            if !existing.enabled || existing.id == rule.id {
                continue;
            }
            if let Some(c) = conflict::check_conflict(existing, rule) {
                conflicts.push(c);
            }
        }
        conflicts
    }

    pub fn get_all_stats(&self) -> Vec<RuleStats> {
        let shared = self.shared_stats.lock();
        let mut stats: Vec<RuleStats> = self.rule_stats.values().cloned().collect();
        for (id, shared_stat) in shared.iter() {
            if let Some(local) = stats.iter_mut().find(|s| s.rule_id == *id) {
                local.total_triggers = local.total_triggers.max(shared_stat.total_triggers);
                local.triggers_last_24h = shared_stat.triggers_last_24h;
                local.last_trigger_time = shared_stat.last_trigger_time.or(local.last_trigger_time);
            } else {
                stats.push(shared_stat.clone());
            }
        }
        for rule in &self.rules {
            if !stats.iter().any(|s| s.rule_id == rule.id) {
                stats.push(RuleStats {
                    rule_id: rule.id.clone(),
                    ..Default::default()
                });
            }
        }
        for stat in &mut stats {
            stat.last_24h_triggers = stat.triggers_last_24h;
        }
        stats
    }

    pub fn increment_rule_stat(&mut self, rule_id: &str) {
        let now = current_timestamp_secs();
        let stat = self.rule_stats.entry(rule_id.to_string()).or_insert_with(|| RuleStats {
            rule_id: rule_id.to_string(),
            ..Default::default()
        });
        stat.total_triggers += 1;
        stat.last_24h_triggers += 1;
        if stat.first_trigger_time.is_none() {
            stat.first_trigger_time = Some(now);
        }
        stat.last_trigger_time = Some(now);
    }

    pub fn batch_toggle(&mut self, rule_ids: &[String], enabled: bool) -> Result<(), String> {
        let now = current_timestamp_secs();
        for id in rule_ids {
            if let Some(rule) = self.rules.iter_mut().find(|r| r.id == *id) {
                rule.enabled = enabled;
                rule.updated_at = now;
            }
        }
        self.refresh_engine();
        self.save_to_disk()?;
        Ok(())
    }

    pub fn batch_delete(&mut self, rule_ids: &[String]) -> Result<(), String> {
        let id_set: std::collections::HashSet<String> = rule_ids.iter().cloned().collect();
        self.rules.retain(|r| !id_set.contains(&r.id));
        for id in rule_ids {
            self.rule_stats.remove(id);
        }
        self.refresh_engine();
        self.save_to_disk()?;
        Ok(())
    }

    pub fn batch_move_to_group(&mut self, rule_ids: &[String], group_id: Option<&str>) -> Result<(), String> {
        if let Some(gid) = group_id {
            if !self.groups.iter().any(|g| g.id == gid) {
                return Err("目标分组不存在".to_string());
            }
        }
        for id in rule_ids {
            if let Some(rule) = self.rules.iter_mut().find(|r| r.id == *id) {
                rule.group = group_id.map(|g| g.to_string());
                rule.updated_at = current_timestamp_secs();
            }
        }
        self.save_to_disk()?;
        Ok(())
    }

    pub fn add_group(&mut self, group: RuleGroup) -> Result<(), String> {
        if self.groups.iter().any(|g| g.id == group.id) {
            return Err("分组ID已存在".to_string());
        }
        self.groups.push(group);
        self.save_to_disk()?;
        Ok(())
    }

    pub fn update_group(&mut self, group: RuleGroup) -> Result<(), String> {
        if let Some(existing) = self.groups.iter_mut().find(|g| g.id == group.id) {
            *existing = group;
            self.save_to_disk()?;
            Ok(())
        } else {
            Err("分组不存在".to_string())
        }
    }

    pub fn delete_group(&mut self, group_id: &str) -> Result<(), String> {
        self.groups.retain(|g| g.id != group_id);
        for rule in &mut self.rules {
            if rule.group.as_deref() == Some(group_id) {
                rule.group = None;
            }
        }
        self.refresh_engine();
        self.save_to_disk()?;
        Ok(())
    }

    pub fn export_rules(&self, rule_ids: Option<&[String]>) -> Result<RulesFile, String> {
        let rules_file = RulesFile {
            version: "1.0".to_string(),
            groups: self.groups.clone(),
            rules: self.rules.clone(),
            rule_stats: Vec::new(),
        };

        if let Some(ids) = rule_ids {
            let filtered_rules: Vec<DetectionRule> = rules_file.rules
                .into_iter()
                .filter(|r| ids.contains(&r.id))
                .collect();

            let group_ids: std::collections::HashSet<String> = filtered_rules
                .iter()
                .filter_map(|r| r.group.clone())
                .collect();

            let filtered_groups: Vec<RuleGroup> = rules_file.groups
                .into_iter()
                .filter(|g| group_ids.contains(&g.id))
                .collect();

            Ok(RulesFile {
                version: rules_file.version,
                groups: filtered_groups,
                rules: filtered_rules,
                rule_stats: Vec::new(),
            })
        } else {
            Ok(rules_file)
        }
    }

    pub fn import_rules(&mut self, import_data: &RulesFile) -> Result<usize, String> {
        let mut imported = 0;

        for group in &import_data.groups {
            if !self.groups.iter().any(|g| g.id == group.id) {
                self.groups.push(group.clone());
            }
        }

        for rule in &import_data.rules {
            if self.rules.len() >= persistence::max_rules() {
                break;
            }
            if !self.rules.iter().any(|r| r.id == rule.id) {
                self.rule_stats.insert(rule.id.clone(), RuleStats {
                    rule_id: rule.id.clone(),
                    ..Default::default()
                });
                self.rules.push(rule.clone());
                imported += 1;
            }
        }

        self.refresh_engine();
        self.save_to_disk()?;
        Ok(imported)
    }

    pub fn start_worker(&mut self) {
        if self.worker_handle.is_some() {
            return;
        }

        let rx = self.rx.take().unwrap();
        let stop_flag = self.stop_flag.clone();
        let alert_tx = self.alert_tx.clone().unwrap();
        let rule_engine = self.rule_engine.clone();
        let action_executor = self.action_executor.clone();
        let shared_stats = self.shared_stats.clone();
        let response_executor = self.response_executor.clone();

        let handle = std::thread::Builder::new()
            .name("rule-engine-worker".into())
            .spawn(move || {
                worker_loop(rx, stop_flag, alert_tx, rule_engine, action_executor, shared_stats, response_executor);
            })
            .unwrap();

        self.worker_handle = Some(handle);
    }

    pub fn stop_worker(&mut self) {
        self.stop_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.join();
        }
    }

    pub fn submit_packet(&self, meta: PacketMetadata, raw_data: Vec<u8>) {
        if let Some(ref tx) = self.tx {
            let _ = tx.try_send(RulePacketEvent { meta, raw_data });
        }
    }

    pub fn get_sender(&self) -> Option<Sender<RulePacketEvent>> {
        self.tx.clone()
    }

    pub fn drain_new_alerts(&mut self) -> Vec<AlertRecord> {
        if let Some(ref rx) = *self.alert_rx.lock() {
            let mut new_alerts = Vec::new();
            while let Ok(alert) = rx.try_recv() {
                if self.alerts.len() >= MAX_ALERTS {
                    self.alerts.pop_front();
                }
                self.alerts.push_back(alert.clone());
                new_alerts.push(alert);
            }
            new_alerts
        } else {
            Vec::new()
        }
    }

    pub fn clear_alerts(&mut self) {
        self.alerts.clear();
    }

    pub fn clear_rate_counters(&mut self) {
        let mut engine = self.rule_engine.lock();
        engine.clear_rate_counters();
    }

    pub fn max_rules(&self) -> usize {
        persistence::max_rules()
    }

    pub fn max_alerts(&self) -> usize {
        MAX_ALERTS
    }

    pub fn get_response_logs(&self) -> Vec<ResponseLogEntry> {
        self.response_executor.lock().get_logs()
    }

    pub fn get_response_logs_filtered(&self, rule_name: &str, time_from: Option<u64>, time_to: Option<u64>) -> Vec<ResponseLogEntry> {
        self.response_executor.lock().filter_logs(rule_name, time_from, time_to)
    }

    pub fn clear_response_logs(&self) {
        self.response_executor.lock().clear_logs();
    }

    pub fn get_ban_entries(&self) -> Vec<BanEntry> {
        self.ban_list.lock().get_all_entries()
    }

    pub fn unban_ip(&self, ip: &str) -> Result<(), String> {
        self.ban_list.lock().unban(ip)
    }

    pub fn cleanup_expired_bans(&self) -> Result<usize, String> {
        self.ban_list.lock().cleanup_expired()
    }

    pub fn clear_all_bans(&self) -> Result<(), String> {
        self.ban_list.lock().clear_all()
    }

    pub fn is_ip_banned(&self, addr: &str) -> bool {
        self.ban_list.lock().is_banned(addr)
    }

    pub fn check_ban_match(&self, src_addr: &str, dst_addr: &str) -> bool {
        self.ban_list.lock().check_ip_match(src_addr, dst_addr)
    }

    pub fn get_response_config(&self) -> ResponseConfig {
        self.response_config.lock().clone()
    }

    pub fn save_response_config(&self, config: ResponseConfig) -> Result<(), String> {
        *self.response_config.lock() = config.clone();

        if let Some(ref dir) = self.app_data_dir {
            let config_path = dir.join("response_config.json");
            let content = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
            std::fs::write(&config_path, content).map_err(|e| e.to_string())?;

            let ban_path = dir.join(&config.ban_list_path);
            self.ban_list.lock().set_file_path(ban_path);
        }

        Ok(())
    }
}

impl Default for RuleManager {
    fn default() -> Self {
        Self::new()
    }
}

fn worker_loop(
    rx: Receiver<RulePacketEvent>,
    stop_flag: Arc<std::sync::atomic::AtomicBool>,
    alert_tx: crossbeam_channel::Sender<AlertRecord>,
    rule_engine: Arc<Mutex<RuleEngine>>,
    action_executor: Arc<Mutex<AlertActionExecutor>>,
    shared_stats: Arc<Mutex<HashMap<String, RuleStats>>>,
    response_executor: Arc<Mutex<ResponseExecutor>>,
) {
    while !stop_flag.load(std::sync::atomic::Ordering::SeqCst) {
        match rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(event) => {
                let meta = event.meta;
                let raw_data = event.raw_data;

                let raw_packet = RawPacket {
                    timestamp_secs: meta.timestamp_secs,
                    timestamp_micros: meta.timestamp_micros,
                    data: raw_data.clone(),
                };

                let matched_rules = {
                    let mut engine = rule_engine.lock();
                    engine.record_packet_for_rate(&meta);
                    engine.evaluate_packet(&meta, &raw_data, None)
                };

                for rule in matched_rules {
                    let alert = AlertRecord {
                        id: generate_alert_id(),
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        priority: rule.priority,
                        packet_no: meta.no,
                        timestamp_secs: meta.timestamp_secs,
                        timestamp_micros: meta.timestamp_micros,
                        match_summary: generate_match_summary(&rule.condition, &meta),
                        src_addr: meta.src_addr.clone(),
                        dst_addr: meta.dst_addr.clone(),
                        protocol: meta.protocol.as_str().to_string(),
                    };

                    {
                        let executor = action_executor.lock();
                        executor.execute_actions(&rule, meta.no, Some(&raw_packet));
                    }

                    if !rule.response_actions.is_empty() {
                        ResponseExecutor::execute_response_chain_async(
                            response_executor.clone(),
                            rule.clone(),
                            meta.src_addr.clone(),
                            meta.dst_addr.clone(),
                            meta.protocol.as_str().to_string(),
                            alert.match_summary.clone(),
                            meta.timestamp_secs,
                        );
                    }

                    {
                        let mut stats_map = shared_stats.lock();
                        let stat = stats_map.entry(rule.id.clone()).or_insert_with(|| RuleStats {
                            rule_id: rule.id.clone(),
                            ..Default::default()
                        });
                        stat.total_triggers += 1;
                        if stat.first_trigger_time.is_none() {
                            stat.first_trigger_time = Some(meta.timestamp_secs);
                        }
                        stat.last_trigger_time = Some(meta.timestamp_secs);
                        let cutoff = meta.timestamp_secs.saturating_sub(86400);
                        if stat.last_24h_window_start < cutoff {
                            let triggers_in_window: u64 = stat.recent_triggers.iter().filter(|&&t| t >= cutoff).count() as u64;
                            stat.triggers_last_24h = triggers_in_window;
                            stat.last_24h_window_start = cutoff;
                            stat.recent_triggers.retain(|&t| t >= cutoff);
                        }
                        stat.triggers_last_24h += 1;
                        stat.recent_triggers.push(meta.timestamp_secs);
                        if stat.recent_triggers.len() > 10000 {
                            stat.recent_triggers.drain(0..1000);
                        }
                    }

                    let _ = alert_tx.send(alert);
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn generate_alert_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("alert_{}", nanos)
}

fn generate_match_summary(condition: &ConditionNode, meta: &PacketMetadata) -> String {
    let mut parts = Vec::new();
    collect_match_parts(condition, meta, &mut parts);
    if parts.is_empty() {
        "匹配成功".to_string()
    } else {
        parts.join("; ")
    }
}

fn collect_match_parts(node: &ConditionNode, meta: &PacketMetadata, parts: &mut Vec<String>) {
    match node {
        ConditionNode::And { children } | ConditionNode::Or { children } => {
            for child in children {
                collect_match_parts(child, meta, parts);
            }
        }
        ConditionNode::Not { child } => {
            collect_match_parts(child, meta, parts);
        }
        ConditionNode::ProtocolMatch { protocol } => {
            parts.push(format!("协议: {}", protocol));
        }
        ConditionNode::IpMatch { field, cidr } => {
            let field_name = match field {
                IpField::Src => "源IP",
                IpField::Dst => "目的IP",
                IpField::Either => "IP",
            };
            parts.push(format!("{}匹配: {}", field_name, cidr));
        }
        ConditionNode::PortRange { field, min, max } => {
            let field_name = match field {
                PortField::Src => "源端口",
                PortField::Dst => "目的端口",
                PortField::Either => "端口",
            };
            parts.push(format!("{}范围: {}-{}", field_name, min, max));
        }
        ConditionNode::PacketLength { operator, value } => {
            let op = match operator {
                LengthOperator::GreaterThan => ">",
                LengthOperator::LessThan => "<",
                LengthOperator::Equal => "==",
            };
            parts.push(format!("包长{} {}", op, value));
        }
        ConditionNode::TcpFlags { flags, mode: _ } => {
            let flag_strs: Vec<String> = flags.iter().map(|f| format!("{:?}", f)).collect();
            parts.push(format!("TCP标志: {}", flag_strs.join(",")));
        }
        ConditionNode::PayloadKeyword { pattern, compiled: _ } => {
            parts.push(format!("载荷关键字: {}", pattern));
        }
        ConditionNode::RateLimit { window_secs, threshold, src_ip } => {
            let dir = if *src_ip { "源IP" } else { "目的IP" };
            parts.push(format!("速率超限({}s/{}包) - {}", window_secs, threshold, dir));
        }
        ConditionNode::DnsBlacklist { domains: _ } => {
            parts.push("DNS黑名单匹配".to_string());
        }
    }
}

fn generate_condition_summary(condition: &ConditionNode) -> String {
    let mut parts = Vec::new();
    collect_summary_parts(condition, &mut parts, 3);
    if parts.is_empty() {
        "空条件".to_string()
    } else {
        parts.join("; ")
    }
}

fn collect_summary_parts(node: &ConditionNode, parts: &mut Vec<String>, limit: usize) {
    if parts.len() >= limit {
        return;
    }
    match node {
        ConditionNode::And { children } | ConditionNode::Or { children } => {
            for child in children {
                collect_summary_parts(child, parts, limit);
                if parts.len() >= limit {
                    return;
                }
            }
        }
        ConditionNode::Not { child } => {
            collect_summary_parts(child, parts, limit);
        }
        ConditionNode::ProtocolMatch { protocol } => {
            parts.push(format!("协议:{}", protocol));
        }
        ConditionNode::IpMatch { field, cidr } => {
            let f = match field {
                IpField::Src => "源",
                IpField::Dst => "目的",
                IpField::Either => "",
            };
            parts.push(format!("{}IP:{}", f, cidr));
        }
        ConditionNode::PortRange { field, min, max } => {
            let f = match field {
                PortField::Src => "源",
                PortField::Dst => "目的",
                PortField::Either => "",
            };
            parts.push(format!("{}端口:{}-{}", f, min, max));
        }
        ConditionNode::PacketLength { operator, value } => {
            let op = match operator {
                LengthOperator::GreaterThan => ">",
                LengthOperator::LessThan => "<",
                LengthOperator::Equal => "==",
            };
            parts.push(format!("包长{}{}", op, value));
        }
        ConditionNode::TcpFlags { flags, .. } => {
            let s: Vec<String> = flags.iter().map(|f| format!("{:?}", f)).collect();
            parts.push(format!("TCP:{}", s.join(",")));
        }
        ConditionNode::PayloadKeyword { pattern, .. } => {
            parts.push(format!("载荷:{}", pattern));
        }
        ConditionNode::RateLimit { window_secs, threshold, .. } => {
            parts.push(format!("速率:{}/{}s", threshold, window_secs));
        }
        ConditionNode::DnsBlacklist { domains } => {
            parts.push(format!("DNS黑名单:{}个", domains.len()));
        }
    }
}

fn strip_compiled_regex(node: ConditionNode) -> ConditionNode {
    match node {
        ConditionNode::And { children } => ConditionNode::And {
            children: children.into_iter().map(strip_compiled_regex).collect(),
        },
        ConditionNode::Or { children } => ConditionNode::Or {
            children: children.into_iter().map(strip_compiled_regex).collect(),
        },
        ConditionNode::Not { child } => ConditionNode::Not {
            child: Box::new(strip_compiled_regex(*child)),
        },
        ConditionNode::PayloadKeyword { pattern, .. } => ConditionNode::PayloadKeyword {
            pattern,
            compiled: None,
        },
        other => other,
    }
}

fn current_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
