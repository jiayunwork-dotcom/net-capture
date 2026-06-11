use std::sync::Arc;
use std::collections::VecDeque;
use parking_lot::Mutex;
use crossbeam_channel::{Sender, Receiver, bounded};
use crate::models::{PacketMetadata, RawPacket};
use super::models::*;
use super::engine::RuleEngine;
use super::actions::AlertActionExecutor;
use super::persistence;

pub const MAX_ALERTS: usize = 50_000;

pub enum RuleManagerEvent {
    NewPacket(PacketMetadata, Vec<u8>),
}

pub struct RuleManager {
    rules: Vec<DetectionRule>,
    groups: Vec<RuleGroup>,
    alerts: VecDeque<AlertRecord>,
    rule_engine: Arc<Mutex<RuleEngine>>,
    action_executor: Arc<Mutex<AlertActionExecutor>>,
    app_data_dir: Option<std::path::PathBuf>,
    tx: Option<Sender<RuleManagerEvent>>,
    rx: Option<Receiver<RuleManagerEvent>>,
    worker_handle: Option<std::thread::JoinHandle<()>>,
    stop_flag: Arc<std::sync::atomic::AtomicBool>,
    alert_tx: Option<crossbeam_channel::Sender<AlertRecord>>,
    alert_rx: Arc<Mutex<Option<crossbeam_channel::Receiver<AlertRecord>>>>,
}

impl RuleManager {
    pub fn new() -> Self {
        let (tx, rx) = bounded(10000);
        let (alert_tx, alert_rx) = bounded(1000);

        Self {
            rules: Vec::new(),
            groups: Vec::new(),
            alerts: VecDeque::new(),
            rule_engine: Arc::new(Mutex::new(RuleEngine::new())),
            action_executor: Arc::new(Mutex::new(AlertActionExecutor::new())),
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
        self.app_data_dir = Some(path);
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
            self.refresh_engine();
        }
        Ok(())
    }

    pub fn save_to_disk(&self) -> Result<(), String> {
        if let Some(ref dir) = self.app_data_dir {
            let rules_file = RulesFile {
                version: "1.0".to_string(),
                groups: self.groups.clone(),
                rules: self.rules.clone(),
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

        self.rules.push(rule);
        self.refresh_engine();
        self.save_to_disk()?;
        Ok(())
    }

    pub fn update_rule(&mut self, mut rule: DetectionRule) -> Result<(), String> {
        let _ = super::engine::compile_regex_in_rule(&mut rule)?;

        if let Some(existing) = self.rules.iter_mut().find(|r| r.id == rule.id) {
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

        let handle = std::thread::Builder::new()
            .name("rule-engine-worker".into())
            .spawn(move || {
                worker_loop(rx, stop_flag, alert_tx, rule_engine, action_executor);
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
            let _ = tx.send(RuleManagerEvent::NewPacket(meta, raw_data));
        }
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
}

impl Default for RuleManager {
    fn default() -> Self {
        Self::new()
    }
}

fn worker_loop(
    rx: Receiver<RuleManagerEvent>,
    stop_flag: Arc<std::sync::atomic::AtomicBool>,
    alert_tx: crossbeam_channel::Sender<AlertRecord>,
    rule_engine: Arc<Mutex<RuleEngine>>,
    action_executor: Arc<Mutex<AlertActionExecutor>>,
) {
    while !stop_flag.load(std::sync::atomic::Ordering::SeqCst) {
        match rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(RuleManagerEvent::NewPacket(meta, raw_data)) => {
                let raw_packet = RawPacket {
                    timestamp_secs: meta.timestamp_secs,
                    timestamp_micros: meta.timestamp_micros,
                    data: raw_data.clone(),
                };

                let matched_rules = {
                    let mut engine = rule_engine.lock();
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

fn current_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
