use tauri::State;
use crate::AppState;
use crate::rule::models::*;
use crate::rule::parser::{parse_expression, node_to_expression, validate_cidr};
use crate::rule::engine::compile_regex_in_rule;

#[tauri::command]
pub fn get_rules(state: State<'_, AppState>) -> Result<Vec<DetectionRule>, String> {
    let manager = state.rule_manager.lock();
    Ok(manager.get_rules())
}

#[tauri::command]
pub fn get_rule_groups(state: State<'_, AppState>) -> Result<Vec<RuleGroup>, String> {
    let manager = state.rule_manager.lock();
    Ok(manager.get_groups())
}

#[tauri::command]
pub fn add_rule(
    state: State<'_, AppState>,
    rule: DetectionRule,
) -> Result<(), String> {
    let mut manager = state.rule_manager.lock();
    manager.add_rule(rule)
}

#[tauri::command]
pub fn update_rule(
    state: State<'_, AppState>,
    rule: DetectionRule,
) -> Result<(), String> {
    let mut manager = state.rule_manager.lock();
    manager.update_rule(rule)
}

#[tauri::command]
pub fn delete_rule(
    state: State<'_, AppState>,
    rule_id: String,
) -> Result<(), String> {
    let mut manager = state.rule_manager.lock();
    manager.delete_rule(&rule_id)
}

#[tauri::command]
pub fn toggle_rule(
    state: State<'_, AppState>,
    rule_id: String,
    enabled: bool,
) -> Result<(), String> {
    let mut manager = state.rule_manager.lock();
    manager.toggle_rule(&rule_id, enabled)
}

#[tauri::command]
pub fn add_rule_group(
    state: State<'_, AppState>,
    group: RuleGroup,
) -> Result<(), String> {
    let mut manager = state.rule_manager.lock();
    manager.add_group(group)
}

#[tauri::command]
pub fn update_rule_group(
    state: State<'_, AppState>,
    group: RuleGroup,
) -> Result<(), String> {
    let mut manager = state.rule_manager.lock();
    manager.update_group(group)
}

#[tauri::command]
pub fn delete_rule_group(
    state: State<'_, AppState>,
    group_id: String,
) -> Result<(), String> {
    let mut manager = state.rule_manager.lock();
    manager.delete_group(&group_id)
}

#[tauri::command]
pub fn parse_rule_expression(
    expression: String,
) -> Result<ConditionNode, ParseError> {
    parse_expression(&expression)
}

#[tauri::command]
pub fn node_to_expression_string(
    node: ConditionNode,
) -> Result<String, String> {
    Ok(node_to_expression(&node))
}

#[tauri::command]
pub fn validate_rule_regex(
    pattern: String,
) -> Result<bool, String> {
    match regex::Regex::new(&pattern) {
        Ok(_) => Ok(true),
        Err(e) => Err(format!("正则表达式无效: {}", e)),
    }
}

#[tauri::command]
pub fn validate_rule_cidr(
    cidr: String,
) -> Result<bool, String> {
    Ok(validate_cidr(&cidr))
}

#[tauri::command]
pub fn get_alerts(state: State<'_, AppState>) -> Result<Vec<AlertRecord>, String> {
    let mut manager = state.rule_manager.lock();
    let _ = manager.drain_new_alerts();
    Ok(manager.get_alerts())
}

#[tauri::command]
pub fn get_new_alerts(state: State<'_, AppState>) -> Result<Vec<AlertRecord>, String> {
    let mut manager = state.rule_manager.lock();
    Ok(manager.drain_new_alerts())
}

#[tauri::command]
pub fn get_alert_count(state: State<'_, AppState>) -> Result<usize, String> {
    let manager = state.rule_manager.lock();
    Ok(manager.get_alert_count())
}

#[tauri::command]
pub fn clear_alerts(state: State<'_, AppState>) -> Result<(), String> {
    let mut manager = state.rule_manager.lock();
    manager.clear_alerts();
    Ok(())
}

#[tauri::command]
pub fn export_rules_to_file(
    state: State<'_, AppState>,
    path: String,
    rule_ids: Option<Vec<String>>,
) -> Result<(), String> {
    let manager = state.rule_manager.lock();
    let rules_file = manager.export_rules(rule_ids.as_deref())?;

    let content = serde_json::to_string_pretty(&rules_file)
        .map_err(|e| format!("序列化规则失败: {}", e))?;

    std::fs::write(&path, content)
        .map_err(|e| format!("写入文件失败: {}", e))?;

    Ok(())
}

#[tauri::command]
pub fn import_rules_from_file(
    state: State<'_, AppState>,
    path: String,
) -> Result<usize, String> {
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("读取文件失败: {}", e))?;

    let rules_file: RulesFile = serde_json::from_str(&content)
        .map_err(|e| format!("解析规则文件失败: {}", e))?;

    let mut manager = state.rule_manager.lock();
    let count = manager.import_rules(&rules_file)?;

    Ok(count)
}

#[tauri::command]
pub fn get_max_rules(state: State<'_, AppState>) -> Result<usize, String> {
    let manager = state.rule_manager.lock();
    Ok(manager.max_rules())
}

#[tauri::command]
pub fn get_max_alerts(state: State<'_, AppState>) -> Result<usize, String> {
    let manager = state.rule_manager.lock();
    Ok(manager.max_alerts())
}

#[tauri::command]
pub fn compile_rule_regex(
    state: State<'_, AppState>,
    rule_id: String,
) -> Result<(), String> {
    let mut manager = state.rule_manager.lock();
    let rules = manager.get_rules();
    if let Some(mut rule) = rules.into_iter().find(|r| r.id == rule_id) {
        compile_regex_in_rule(&mut rule)?;
        manager.update_rule(rule)?;
    }
    Ok(())
}

#[tauri::command]
pub fn get_rule_versions(
    state: State<'_, AppState>,
    rule_id: String,
) -> Result<Option<Vec<RuleVersion>>, String> {
    let manager = state.rule_manager.lock();
    Ok(manager.get_rule_versions(&rule_id))
}

#[tauri::command]
pub fn rollback_rule_version(
    state: State<'_, AppState>,
    rule_id: String,
    target_version: u32,
) -> Result<(), String> {
    let mut manager = state.rule_manager.lock();
    manager.rollback_rule(&rule_id, target_version)
}

#[tauri::command]
pub fn check_rule_conflicts(
    state: State<'_, AppState>,
    rule: DetectionRule,
) -> Result<Vec<RuleConflict>, String> {
    let manager = state.rule_manager.lock();
    Ok(manager.check_conflicts(&rule))
}

#[tauri::command]
pub fn get_rule_stats(state: State<'_, AppState>) -> Result<Vec<RuleStats>, String> {
    let manager = state.rule_manager.lock();
    Ok(manager.get_all_stats())
}

#[tauri::command]
pub fn batch_toggle_rules(
    state: State<'_, AppState>,
    rule_ids: Vec<String>,
    enabled: bool,
) -> Result<(), String> {
    let mut manager = state.rule_manager.lock();
    manager.batch_toggle(&rule_ids, enabled)
}

#[tauri::command]
pub fn batch_delete_rules(
    state: State<'_, AppState>,
    rule_ids: Vec<String>,
) -> Result<(), String> {
    let mut manager = state.rule_manager.lock();
    manager.batch_delete(&rule_ids)
}

#[tauri::command]
pub fn batch_move_rules_to_group(
    state: State<'_, AppState>,
    rule_ids: Vec<String>,
    group_id: Option<String>,
) -> Result<(), String> {
    let mut manager = state.rule_manager.lock();
    manager.batch_move_to_group(&rule_ids, group_id.as_deref())
}

pub fn init_rule_manager(
    app: &tauri::AppHandle,
    state: &State<'_, AppState>,
) -> Result<(), String> {
    let app_dir = app
        .path_resolver()
        .app_data_dir()
        .ok_or_else(|| "Failed to get app data directory".to_string())?;

    std::fs::create_dir_all(&app_dir).map_err(|e| e.to_string())?;

    let rule_sender = {
        let mut manager = state.rule_manager.lock();
        manager.set_app_data_dir(app_dir);
        manager.set_app_handle(app.clone());
        manager.load_from_disk()?;
        manager.set_capture_engine(state.capture_engine.clone());
        manager.start_worker();
        manager.get_sender()
    };

    if let Some(sender) = rule_sender {
        let mut engine = state.capture_engine.lock();
        engine.set_rule_sender(sender);
    }

    {
        let ban_check = {
            let rm = state.rule_manager.clone();
            Arc::new(move |src: &str, dst: &str| -> bool {
                let mgr = rm.lock();
                mgr.check_ban_match(src, dst)
            }) as Arc<dyn Fn(&str, &str) -> bool + Send + Sync>
        };
        let mut engine = state.capture_engine.lock();
        engine.set_ban_check_fn(ban_check);
    }

    Ok(())
}

use std::sync::Arc;

#[tauri::command]
pub fn get_response_logs(state: State<'_, AppState>) -> Result<Vec<ResponseLogEntry>, String> {
    let manager = state.rule_manager.lock();
    Ok(manager.get_response_logs())
}

#[tauri::command]
pub fn get_response_logs_filtered(
    state: State<'_, AppState>,
    rule_name: String,
    time_from: Option<u64>,
    time_to: Option<u64>,
) -> Result<Vec<ResponseLogEntry>, String> {
    let manager = state.rule_manager.lock();
    Ok(manager.get_response_logs_filtered(&rule_name, time_from, time_to))
}

#[tauri::command]
pub fn clear_response_logs(state: State<'_, AppState>) -> Result<(), String> {
    let manager = state.rule_manager.lock();
    manager.clear_response_logs();
    Ok(())
}

#[tauri::command]
pub fn get_ban_entries(state: State<'_, AppState>) -> Result<Vec<BanEntry>, String> {
    let manager = state.rule_manager.lock();
    Ok(manager.get_ban_entries())
}

#[tauri::command]
pub fn unban_ip(state: State<'_, AppState>, ip: String) -> Result<(), String> {
    let manager = state.rule_manager.lock();
    manager.unban_ip(&ip)
}

#[tauri::command]
pub fn cleanup_expired_bans(state: State<'_, AppState>) -> Result<usize, String> {
    let manager = state.rule_manager.lock();
    manager.cleanup_expired_bans()
}

#[tauri::command]
pub fn clear_all_bans(state: State<'_, AppState>) -> Result<(), String> {
    let manager = state.rule_manager.lock();
    manager.clear_all_bans()
}

#[tauri::command]
pub fn get_response_config(state: State<'_, AppState>) -> Result<ResponseConfig, String> {
    let manager = state.rule_manager.lock();
    Ok(manager.get_response_config())
}

#[tauri::command]
pub fn save_response_config(state: State<'_, AppState>, config: ResponseConfig) -> Result<(), String> {
    let manager = state.rule_manager.lock();
    manager.save_response_config(config)
}
