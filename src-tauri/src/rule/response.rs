use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::io::{BufRead, BufReader};
use parking_lot::Mutex;
use super::models::*;
use super::ban_list::BanListManager;

const MAX_RESPONSE_LOGS: usize = 5000;
const RESPONSE_LOGS_FILENAME: &str = "response_logs.json";

pub struct ResponseExecutor {
    logs: Vec<ResponseLogEntry>,
    ban_list: Arc<Mutex<BanListManager>>,
    response_config: Arc<Mutex<ResponseConfig>>,
    cooldown_map: Arc<Mutex<HashMap<String, u64>>>,
    app_data_dir: Option<PathBuf>,
}

impl ResponseExecutor {
    pub fn new(ban_list: Arc<Mutex<BanListManager>>, config: Arc<Mutex<ResponseConfig>>, app_data_dir: Option<PathBuf>) -> Self {
        let mut executor = Self {
            logs: Vec::new(),
            ban_list,
            response_config: config,
            cooldown_map: Arc::new(Mutex::new(HashMap::new())),
            app_data_dir,
        };
        executor.load_logs();
        executor
    }

    fn get_condition(action: &ResponseAction) -> ConditionMode {
        match action {
            ResponseAction::Webhook { condition, .. } => *condition,
            ResponseAction::IpBan { condition, .. } => *condition,
            ResponseAction::ScriptExec { condition, .. } => *condition,
        }
    }

    fn should_execute(condition: ConditionMode, prev_success: Option<bool>) -> bool {
        match condition {
            ConditionMode::Always => true,
            ConditionMode::OnSuccess => prev_success == Some(true),
            ConditionMode::OnFailure => prev_success == Some(false),
        }
    }

    fn is_result_success(result: &ResponseResult) -> bool {
        matches!(result, ResponseResult::Success)
    }

    pub fn execute_response_chain_async(
        self_arc: Arc<Mutex<Self>>,
        rule: DetectionRule,
        src_addr: String,
        dst_addr: String,
        protocol: String,
        match_summary: String,
        timestamp_secs: u64,
    ) {
        std::thread::spawn(move || {
            if rule.response_actions.is_empty() {
                return;
            }

            {
                let mut executor = self_arc.lock();
                let cooldown = if rule.cooldown_secs > 0 {
                    rule.cooldown_secs
                } else {
                    let config = executor.response_config.lock();
                    config.default_cooldown_secs
                };

                if executor.check_cooldown(&rule.id, timestamp_secs, cooldown) {
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
                    executor.add_log(entry);
                    return;
                }

                executor.update_cooldown(&rule.id, timestamp_secs);
            }

            if rule.parallel_execution {
                Self::execute_parallel(self_arc, &rule, &src_addr, &dst_addr, &protocol, &match_summary, timestamp_secs);
            } else {
                Self::execute_serial(self_arc, &rule, &src_addr, &dst_addr, &protocol, &match_summary, timestamp_secs);
            }
        });
    }

    fn execute_serial(
        self_arc: Arc<Mutex<Self>>,
        rule: &DetectionRule,
        src_addr: &str,
        dst_addr: &str,
        protocol: &str,
        match_summary: &str,
        timestamp_secs: u64,
    ) {
        let chain_start = std::time::Instant::now();
        let mut prev_success: Option<bool> = None;

        for (index, action) in rule.response_actions.iter().enumerate() {
            let condition = Self::get_condition(action);

            if index > 0 && !Self::should_execute(condition, prev_success) {
                let entry = ResponseLogEntry {
                    id: generate_response_id(),
                    trigger_time: timestamp_secs,
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    action_type: action_type_str(action),
                    result: ResponseResult::ConditionSkipped,
                    duration_ms: 0,
                    detail: Some(format!(
                        "前置条件不满足({:?}), 跳过执行",
                        condition
                    )),
                };
                let mut executor = self_arc.lock();
                executor.add_log(entry);
                continue;
            }

            let entry = {
                let executor = self_arc.lock();
                executor.execute_action(
                    action,
                    rule,
                    src_addr,
                    dst_addr,
                    protocol,
                    match_summary,
                    timestamp_secs,
                )
            };

            prev_success = Some(Self::is_result_success(&entry.result));

            {
                let mut executor = self_arc.lock();
                executor.add_log(entry);
            }
        }

        let total_ms = chain_start.elapsed().as_millis() as u64;
        let summary_entry = ResponseLogEntry {
            id: generate_response_id(),
            trigger_time: timestamp_secs,
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            action_type: "chain".to_string(),
            result: ResponseResult::Success,
            duration_ms: total_ms,
            detail: Some(format!(
                "串行执行完成, 总耗时: {}ms, 动作数: {}",
                total_ms,
                rule.response_actions.len()
            )),
        };
        {
            let mut executor = self_arc.lock();
            executor.add_log(summary_entry);
        }
    }

    fn execute_parallel(
        self_arc: Arc<Mutex<Self>>,
        rule: &DetectionRule,
        src_addr: &str,
        dst_addr: &str,
        protocol: &str,
        match_summary: &str,
        timestamp_secs: u64,
    ) {
        let chain_start = std::time::Instant::now();
        let actions_len = rule.response_actions.len();
        let results: Arc<Mutex<Vec<Option<(ResponseLogEntry, bool)>>>> = Arc::new(Mutex::new(vec![None; actions_len]));
        let completed: Arc<Mutex<HashMap<usize, bool>>> = Arc::new(Mutex::new(HashMap::new()));

        let mut handles = Vec::new();

        for (index, action) in rule.response_actions.iter().enumerate() {
            let condition = Self::get_condition(action);
            let self_arc_clone = self_arc.clone();
            let rule_clone = rule.clone();
            let src = src_addr.to_string();
            let dst = dst_addr.to_string();
            let proto = protocol.to_string();
            let summary = match_summary.to_string();
            let results_clone = results.clone();
            let completed_clone = completed.clone();
            let action_clone = action.clone();

            let handle = std::thread::spawn(move || {
                if index > 0 && condition != ConditionMode::Always {
                    let wait_for = match condition {
                        ConditionMode::OnSuccess => true,
                        ConditionMode::OnFailure => false,
                        ConditionMode::Always => unreachable!(),
                    };

                    loop {
                        let comp = completed_clone.lock();
                        let has_dep = (index > 0).then(|| comp.get(&(index - 1)).copied());
                        drop(comp);

                        match has_dep {
                            Some(Some(dep_result)) => {
                                if dep_result != wait_for {
                                    let entry = ResponseLogEntry {
                                        id: generate_response_id(),
                                        trigger_time: timestamp_secs,
                                        rule_id: rule_clone.id.clone(),
                                        rule_name: rule_clone.name.clone(),
                                        action_type: action_type_str(&action_clone),
                                        result: ResponseResult::ConditionSkipped,
                                        duration_ms: 0,
                                        detail: Some(format!(
                                            "前置条件不满足({:?}), 跳过执行",
                                            condition
                                        )),
                                    };
                                    let mut res = results_clone.lock();
                                    res[index] = Some((entry, false));
                                    let mut comp = completed_clone.lock();
                                    comp.insert(index, false);
                                    return;
                                }
                                break;
                            }
                            None => break,
                            Some(None) => {
                                drop(has_dep);
                                std::thread::sleep(std::time::Duration::from_millis(10));
                            }
                        }
                    }
                }

                let entry = {
                    let executor = self_arc_clone.lock();
                    executor.execute_action(
                        &action_clone,
                        &rule_clone,
                        &src,
                        &dst,
                        &proto,
                        &summary,
                        timestamp_secs,
                    )
                };

                let success = Self::is_result_success(&entry.result);

                {
                    let mut res = results_clone.lock();
                    res[index] = Some((entry, success));
                }
                {
                    let mut comp = completed_clone.lock();
                    comp.insert(index, success);
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.join();
        }

        let total_ms = chain_start.elapsed().as_millis() as u64;
        let mut max_action_ms: u64 = 0;
        {
            let res = results.lock();
            for opt in res.iter() {
                if let Some((entry, _success)) = opt {
                    if entry.duration_ms > max_action_ms {
                        max_action_ms = entry.duration_ms;
                    }
                    let mut executor = self_arc.lock();
                    executor.add_log(entry.clone());
                }
            }
        }

        let summary_entry = ResponseLogEntry {
            id: generate_response_id(),
            trigger_time: timestamp_secs,
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            action_type: "chain".to_string(),
            result: ResponseResult::Success,
            duration_ms: total_ms,
            detail: Some(format!(
                "并行执行完成, 总耗时: {}ms (最长单动作: {}ms), 动作数: {}",
                total_ms,
                max_action_ms,
                rule.response_actions.len()
            )),
        };
        {
            let mut executor = self_arc.lock();
            executor.add_log(summary_entry);
        }
    }

    #[allow(dead_code)]
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

        let mut prev_success: Option<bool> = None;

        for (index, action) in rule.response_actions.iter().enumerate() {
            let condition = Self::get_condition(action);

            if index > 0 && !Self::should_execute(condition, prev_success) {
                let entry = ResponseLogEntry {
                    id: generate_response_id(),
                    trigger_time: timestamp_secs,
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    action_type: action_type_str(action),
                    result: ResponseResult::ConditionSkipped,
                    duration_ms: 0,
                    detail: Some(format!(
                        "前置条件不满足({:?}), 跳过执行",
                        condition
                    )),
                };
                self.add_log(entry.clone());
                entries.push(entry);
                continue;
            }

            let entry = self.execute_action(
                action,
                rule,
                src_addr,
                dst_addr,
                protocol,
                match_summary,
                timestamp_secs,
            );
            prev_success = Some(Self::is_result_success(&entry.result));
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
            ResponseAction::Webhook { url, headers, timeout_secs, .. } => {
                self.execute_webhook(rule, url, headers, *timeout_secs, src_addr, dst_addr, protocol, match_summary, timestamp_secs)
            }
            ResponseAction::IpBan { target, expire_minutes, .. } => {
                self.execute_ip_ban(rule, target, *expire_minutes, src_addr, dst_addr, timestamp_secs)
            }
            ResponseAction::ScriptExec { path, args_template, timeout_secs, .. } => {
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
                related_alerts_count: 0,
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

        let args_vec = split_args(&resolved_args);

        let mut child = match std::process::Command::new(path)
            .args(&args_vec)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                return ResponseLogEntry {
                    id: generate_response_id(),
                    trigger_time: timestamp_secs,
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    action_type: "script_exec".to_string(),
                    result: ResponseResult::Failed,
                    duration_ms,
                    detail: Some(format!("启动进程失败: {}", e)),
                };
            }
        };

        let child_id = child.id();

        let result = if let Ok(()) = child.wait_timeout(timeout) {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let stdout = child.stdout.take().map(|pipe| {
                        BufReader::new(pipe).lines().filter_map(|l| l.ok()).collect::<Vec<_>>().join("\n")
                    }).unwrap_or_default();
                    let stderr = child.stderr.take().map(|pipe| {
                        BufReader::new(pipe).lines().filter_map(|l| l.ok()).collect::<Vec<_>>().join("\n")
                    }).unwrap_or_default();

                    if status.success() {
                        Ok(stdout)
                    } else {
                        let exit_code = status.code().unwrap_or(-1);
                        Err((
                            ResponseResult::Failed,
                            format!("退出码: {}, stderr: {}", exit_code, stderr.chars().take(200).collect::<String>()),
                        ))
                    }
                }
                _ => {
                    Err((ResponseResult::Failed, "无法获取进程状态".to_string()))
                }
            }
        } else {
            if child_id > 0 {
                #[cfg(unix)]
                {
                    let _ = unsafe { libc_kill(child_id as i32, libc_sigterm()) };
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    let _ = child.try_wait();
                    let _ = unsafe { libc_kill(child_id as i32, libc_sigkill()) };
                }
                #[cfg(windows)]
                {
                    let _ = child.kill();
                }
                let _ = child.wait();
            }
            Err((ResponseResult::Timeout, format!("执行超时({:?})已终止进程", timeout)))
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(stdout) => ResponseLogEntry {
                id: generate_response_id(),
                trigger_time: timestamp_secs,
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                action_type: "script_exec".to_string(),
                result: ResponseResult::Success,
                duration_ms,
                detail: Some(stdout.chars().take(200).collect()),
            },
            Err((result_code, detail)) => ResponseLogEntry {
                id: generate_response_id(),
                trigger_time: timestamp_secs,
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                action_type: "script_exec".to_string(),
                result: result_code,
                duration_ms,
                detail: Some(detail),
            },
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
        self.save_logs();
    }

    pub fn get_logs(&self) -> Vec<ResponseLogEntry> {
        self.logs.iter().rev().cloned().collect()
    }

    pub fn clear_logs(&mut self) {
        self.logs.clear();
        self.save_logs();
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

    fn logs_file_path(&self) -> Option<PathBuf> {
        let dir = self.app_data_dir.as_ref()?;
        Some(dir.join(RESPONSE_LOGS_FILENAME))
    }

    fn load_logs(&mut self) {
        if let Some(path) = self.logs_file_path() {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(mut loaded) = serde_json::from_str::<Vec<ResponseLogEntry>>(&content) {
                        if loaded.len() > MAX_RESPONSE_LOGS {
                            let start = loaded.len() - MAX_RESPONSE_LOGS;
                            loaded = loaded.split_off(start);
                        }
                        self.logs = loaded;
                    }
                }
            }
        }
    }

    fn save_logs(&self) {
        if let Some(path) = self.logs_file_path() {
            if let Ok(content) = serde_json::to_string(&self.logs) {
                let _ = std::fs::write(&path, content);
            }
        }
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

fn split_args(args_str: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut chars = args_str.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
            }
            ' ' | '\t' if !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            '\\' if in_double_quote => {
                if let Some(&next) = chars.peek() {
                    match next {
                        '"' | '\\' | '$' | '`' => {
                            current.push(next);
                            chars.next();
                        }
                        _ => {
                            current.push(c);
                        }
                    }
                } else {
                    current.push(c);
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

#[cfg(unix)]
unsafe fn libc_kill(pid: i32, sig: i32) -> i32 {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    kill(pid, sig)
}

#[cfg(unix)]
fn libc_sigterm() -> i32 { 15 }

#[cfg(unix)]
fn libc_sigkill() -> i32 { 9 }

trait ChildWaitTimeout {
    fn wait_timeout(&mut self, timeout: std::time::Duration) -> Result<(), ()>;
}

impl ChildWaitTimeout for std::process::Child {
    fn wait_timeout(&mut self, timeout: std::time::Duration) -> Result<(), ()> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match self.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(_) => return Err(()),
            }
        }
    }
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

fn action_type_str(action: &ResponseAction) -> String {
    match action {
        ResponseAction::Webhook { .. } => "webhook".to_string(),
        ResponseAction::IpBan { .. } => "ip_ban".to_string(),
        ResponseAction::ScriptExec { .. } => "script_exec".to_string(),
    }
}
