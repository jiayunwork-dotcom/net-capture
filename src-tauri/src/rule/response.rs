use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::Mutex;
use super::models::*;
use super::ban_list::BanListManager;

const MAX_RESPONSE_LOGS: usize = 5000;

pub struct ResponseExecutor {
    logs: Vec<ResponseLogEntry>,
    ban_list: Arc<Mutex<BanListManager>>,
    response_config: Arc<Mutex<ResponseConfig>>,
    cooldown_map: Arc<Mutex<HashMap<String, u64>>>,
}

impl ResponseExecutor {
    pub fn new(ban_list: Arc<Mutex<BanListManager>>, config: Arc<Mutex<ResponseConfig>>) -> Self {
        Self {
            logs: Vec::new(),
            ban_list,
            response_config: config,
            cooldown_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn execute_response_chain(
        &mut self,
        rule: &DetectionRule,
        src_addr: &str,
        dst_addr: &str,
        protocol: &str,
        match_summary: &str,
        timestamp_secs: u64,
    ) -> Vec<ResponseLogEntry> {
        let mut entries = Vec::new();

        if rule.response_actions.is_empty() {
            return entries;
        }

        let cooldown = if rule.cooldown_secs > 0 {
            rule.cooldown_secs
        } else {
            let config = self.response_config.lock();
            config.default_cooldown_secs
        };

        if self.check_cooldown(&rule.id, timestamp_secs, cooldown) {
            let entry = ResponseLogEntry {
                id: generate_response_id(),
                trigger_time: timestamp_secs,
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                action_type: "chain".to_string(),
                result: ResponseResult::CooldownSkipped,
                duration_ms: 0,
                detail: Some(format!("冷却中({}s)", cooldown)),
            };
            entries.push(entry.clone());
            self.add_log(entry);
            return entries;
        }

        self.update_cooldown(&rule.id, timestamp_secs);

        for action in &rule.response_actions {
            let entry = self.execute_action(
                action,
                rule,
                src_addr,
                dst_addr,
                protocol,
                match_summary,
                timestamp_secs,
            );
            self.add_log(entry.clone());
            entries.push(entry);
        }

        entries
    }

    fn execute_action(
        &self,
        action: &ResponseAction,
        rule: &DetectionRule,
        src_addr: &str,
        dst_addr: &str,
        protocol: &str,
        match_summary: &str,
        timestamp_secs: u64,
    ) -> ResponseLogEntry {
        match action {
            ResponseAction::Webhook { url, headers, timeout_secs } => {
                self.execute_webhook(rule, url, headers, *timeout_secs, src_addr, dst_addr, protocol, match_summary, timestamp_secs)
            }
            ResponseAction::IpBan { target, expire_minutes } => {
                self.execute_ip_ban(rule, target, *expire_minutes, src_addr, dst_addr, timestamp_secs)
            }
            ResponseAction::ScriptExec { path, args_template, timeout_secs } => {
                self.execute_script(rule, path, args_template, *timeout_secs, src_addr, dst_addr, protocol, timestamp_secs)
            }
        }
    }

    fn execute_webhook(
        &self,
        rule: &DetectionRule,
        url: &str,
        headers: &HashMap<String, String>,
        timeout_secs: u64,
        src_addr: &str,
        dst_addr: &str,
        protocol: &str,
        match_summary: &str,
        timestamp_secs: u64,
    ) -> ResponseLogEntry {
        let timeout = if timeout_secs > 0 {
            timeout_secs
        } else {
            let config = self.response_config.lock();
            config.webhook_default_timeout_secs
        };

        let body = serde_json::json!({
            "rule_name": rule.name,
            "priority": rule.priority.as_str(),
            "match_summary": match_summary,
            "trigger_time": timestamp_secs,
            "src_addr": src_addr,
            "dst_addr": dst_addr,
            "protocol": protocol,
        });

        let start = std::time::Instant::now();

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout))
            .build();

        let result = match client {
            Ok(client) => {
                let mut req = client.post(url);
                for (key, value) in headers {
                    req = req.header(key.as_str(), value.as_str());
                }
                req = req.json(&body);
                match req.send() {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        if resp.status().is_success() {
                            (ResponseResult::Success, Some(format!("HTTP {}", status)))
                        } else {
                            (ResponseResult::Failed, Some(format!("HTTP {}", status)))
                        }
                    }
                    Err(e) => {
                        let is_timeout = e.is_timeout();
                        if is_timeout {
                            (ResponseResult::Timeout, Some(format!("请求超时: {}", e)))
                        } else {
                            (ResponseResult::Failed, Some(format!("请求失败: {}", e)))
                        }
                    }
                }
            }
            Err(e) => (ResponseResult::Failed, Some(format!("创建HTTP客户端失败: {}", e))),
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        ResponseLogEntry {
            id: generate_response_id(),
            trigger_time: timestamp_secs,
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            action_type: "webhook".to_string(),
            result: result.0,
            duration_ms,
            detail: result.1,
        }
    }

    fn execute_ip_ban(
        &self,
        rule: &DetectionRule,
        target: &BanTarget,
        expire_minutes: u64,
        src_addr: &str,
        dst_addr: &str,
        timestamp_secs: u64,
    ) -> ResponseLogEntry {
        let start = std::time::Instant::now();

        let ips_to_ban: Vec<&str> = match target {
            BanTarget::Src => vec![src_addr],
            BanTarget::Dst => vec![dst_addr],
            BanTarget::Either => {
                let mut ips = Vec::new();
                if !src_addr.is_empty() {
                    ips.push(src_addr);
                }
                if !dst_addr.is_empty() && dst_addr != src_addr {
                    ips.push(dst_addr);
                }
                ips
            }
        };

        let mut banned_ips = Vec::new();
        let mut errors = Vec::new();

        for ip in ips_to_ban {
            if ip.is_empty() {
                continue;
            }
            let entry = BanEntry {
                ip: ip.to_string(),
                ban_time: timestamp_secs,
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                expire_minutes,
            };

            let mut ban_list = self.ban_list.lock();
            match ban_list.add_entry(entry) {
                Ok(_) => banned_ips.push(ip.to_string()),
                Err(e) => errors.push(format!("{}: {}", ip, e)),
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        let result = if errors.is_empty() {
            ResponseResult::Success
        } else {
            ResponseResult::Failed
        };

        let detail = if errors.is_empty() {
            Some(format!("封禁IP: {}", banned_ips.join(", ")))
        } else {
            Some(format!("部分失败: {}", errors.join("; ")))
        };

        ResponseLogEntry {
            id: generate_response_id(),
            trigger_time: timestamp_secs,
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            action_type: "ip_ban".to_string(),
            result,
            duration_ms,
            detail,
        }
    }

    fn execute_script(
        &self,
        rule: &DetectionRule,
        path: &str,
        args_template: &str,
        timeout_secs: u64,
        src_addr: &str,
        dst_addr: &str,
        protocol: &str,
        timestamp_secs: u64,
    ) -> ResponseLogEntry {
        let start = std::time::Instant::now();

        let config = self.response_config.lock();
        let whitelist = config.script_whitelist_dirs.clone();
        drop(config);

        if !is_path_in_whitelist(path, &whitelist) {
            let duration_ms = start.elapsed().as_millis() as u64;
            return ResponseLogEntry {
                id: generate_response_id(),
                trigger_time: timestamp_secs,
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                action_type: "script_exec".to_string(),
                result: ResponseResult::Failed,
                duration_ms,
                detail: Some("脚本路径不在白名单目录内".to_string()),
            };
        }

        let resolved_args = resolve_template_vars(args_template, src_addr, dst_addr, protocol, &rule.name, timestamp_secs);

        let timeout = if timeout_secs > 0 {
            std::time::Duration::from_secs(timeout_secs)
        } else {
            std::time::Duration::from_secs(30)
        };

        let result = std::process::Command::new(path)
            .args(std::iter::once(resolved_args.as_str()).filter(|s| !s.is_empty()))
            .output();

        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    ResponseLogEntry {
                        id: generate_response_id(),
                        trigger_time: timestamp_secs,
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        action_type: "script_exec".to_string(),
                        result: ResponseResult::Success,
                        duration_ms,
                        detail: Some(stdout.chars().take(200).collect()),
                    }
                } else {
                    let exit_code = output.status.code().unwrap_or(-1);
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    ResponseLogEntry {
                        id: generate_response_id(),
                        trigger_time: timestamp_secs,
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        action_type: "script_exec".to_string(),
                        result: ResponseResult::Failed,
                        duration_ms,
                        detail: Some(format!("退出码: {}, stderr: {}", exit_code, stderr.chars().take(200).collect::<String>())),
                    }
                }
            }
            Err(e) => {
                let is_timeout = start.elapsed() > timeout;
                ResponseLogEntry {
                    id: generate_response_id(),
                    trigger_time: timestamp_secs,
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    action_type: "script_exec".to_string(),
                    result: if is_timeout { ResponseResult::Timeout } else { ResponseResult::Failed },
                    duration_ms,
                    detail: Some(format!("执行失败: {}", e)),
                }
            }
        }
    }

    fn check_cooldown(&self, rule_id: &str, now: u64, cooldown_secs: u64) -> bool {
        let map = self.cooldown_map.lock();
        if let Some(&last_time) = map.get(rule_id) {
            now.saturating_sub(last_time) < cooldown_secs
        } else {
            false
        }
    }

    fn update_cooldown(&self, rule_id: &str, now: u64) {
        let mut map = self.cooldown_map.lock();
        map.insert(rule_id.to_string(), now);
    }

    fn add_log(&mut self, entry: ResponseLogEntry) {
        if self.logs.len() >= MAX_RESPONSE_LOGS {
            self.logs.drain(0..100);
        }
        self.logs.push(entry);
    }

    pub fn get_logs(&self) -> Vec<ResponseLogEntry> {
        self.logs.iter().rev().cloned().collect()
    }

    pub fn clear_logs(&mut self) {
        self.logs.clear();
    }

    pub fn filter_logs(&self, rule_name: &str, time_from: Option<u64>, time_to: Option<u64>) -> Vec<ResponseLogEntry> {
        self.logs.iter().rev().filter(|log| {
            if !rule_name.is_empty() && !log.rule_name.to_lowercase().contains(&rule_name.to_lowercase()) {
                return false;
            }
            if let Some(from) = time_from {
                if log.trigger_time < from {
                    return false;
                }
            }
            if let Some(to) = time_to {
                if log.trigger_time > to {
                    return false;
                }
            }
            true
        }).cloned().collect()
    }
}

fn resolve_template_vars(template: &str, src_ip: &str, dst_ip: &str, protocol: &str, rule_name: &str, timestamp: u64) -> String {
    template
        .replace("$SRC_IP", src_ip)
        .replace("$DST_IP", dst_ip)
        .replace("$PROTOCOL", protocol)
        .replace("$RULE_NAME", rule_name)
        .replace("$TIMESTAMP", &timestamp.to_string())
}

fn is_path_in_whitelist(path: &str, whitelist: &[String]) -> bool {
    if whitelist.is_empty() {
        return false;
    }
    let canonical = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(_) => {
            let p = std::path::Path::new(path);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                return false;
            }
        }
    };
    for dir in whitelist {
        let canonical_dir = match std::fs::canonicalize(dir) {
            Ok(p) => p,
            Err(_) => {
                let p = std::path::Path::new(dir);
                if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    continue;
                }
            }
        };
        if canonical.starts_with(&canonical_dir) {
            return true;
        }
    }
    false
}

fn generate_response_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("resp_{}", nanos)
}
