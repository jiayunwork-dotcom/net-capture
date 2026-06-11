use std::fs;
use std::path::PathBuf;
use super::models::*;

const RULES_FILE: &str = "detection_rules.json";
const MAX_RULES: usize = 200;
const MAX_ALERTS: usize = 50_000;

pub fn get_rules_path(app_data_dir: &std::path::Path) -> PathBuf {
    app_data_dir.join(RULES_FILE)
}

pub fn load_rules(app_data_dir: &std::path::Path) -> Result<RulesFile, String> {
    let path = get_rules_path(app_data_dir);
    if !path.exists() {
        return Ok(RulesFile::default());
    }

    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let rules_file: RulesFile = serde_json::from_str(&content)
        .unwrap_or_else(|_| RulesFile::default());
    Ok(rules_file)
}

pub fn save_rules(app_data_dir: &std::path::Path, rules_file: &RulesFile) -> Result<(), String> {
    let path = get_rules_path(app_data_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let content = serde_json::to_string_pretty(rules_file).map_err(|e| e.to_string())?;
    fs::write(&path, content).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn add_rule(app_data_dir: &std::path::Path, rule: DetectionRule) -> Result<(), String> {
    let mut rules_file = load_rules(app_data_dir)?;

    if rules_file.rules.len() >= MAX_RULES {
        return Err(format!("规则数量已达上限({})，请删除旧规则", MAX_RULES));
    }

    if rules_file.rules.iter().any(|r| r.id == rule.id) {
        return Err("规则ID已存在".to_string());
    }

    rules_file.rules.push(rule);
    save_rules(app_data_dir, &rules_file)
}

pub fn update_rule(app_data_dir: &std::path::Path, rule: DetectionRule) -> Result<(), String> {
    let mut rules_file = load_rules(app_data_dir)?;

    if let Some(existing) = rules_file.rules.iter_mut().find(|r| r.id == rule.id) {
        *existing = rule;
        save_rules(app_data_dir, &rules_file)
    } else {
        Err("规则不存在".to_string())
    }
}

pub fn delete_rule(app_data_dir: &std::path::Path, rule_id: &str) -> Result<(), String> {
    let mut rules_file = load_rules(app_data_dir)?;
    rules_file.rules.retain(|r| r.id != rule_id);
    save_rules(app_data_dir, &rules_file)
}

pub fn add_group(app_data_dir: &std::path::Path, group: RuleGroup) -> Result<(), String> {
    let mut rules_file = load_rules(app_data_dir)?;

    if rules_file.groups.iter().any(|g| g.id == group.id) {
        return Err("分组ID已存在".to_string());
    }

    rules_file.groups.push(group);
    save_rules(app_data_dir, &rules_file)
}

pub fn update_group(app_data_dir: &std::path::Path, group: RuleGroup) -> Result<(), String> {
    let mut rules_file = load_rules(app_data_dir)?;

    if let Some(existing) = rules_file.groups.iter_mut().find(|g| g.id == group.id) {
        *existing = group;
        save_rules(app_data_dir, &rules_file)
    } else {
        Err("分组不存在".to_string())
    }
}

pub fn delete_group(app_data_dir: &std::path::Path, group_id: &str) -> Result<(), String> {
    let mut rules_file = load_rules(app_data_dir)?;
    rules_file.groups.retain(|g| g.id != group_id);

    for rule in &mut rules_file.rules {
        if rule.group.as_deref() == Some(group_id) {
            rule.group = None;
        }
    }

    save_rules(app_data_dir, &rules_file)
}

pub fn export_rules(app_data_dir: &std::path::Path, rule_ids: Option<&[String]>) -> Result<RulesFile, String> {
    let rules_file = load_rules(app_data_dir)?;

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

pub fn import_rules(app_data_dir: &std::path::Path, import_data: &RulesFile) -> Result<usize, String> {
    let mut existing = load_rules(app_data_dir)?;
    let mut imported = 0;

    for group in &import_data.groups {
        if !existing.groups.iter().any(|g| g.id == group.id) {
            existing.groups.push(group.clone());
        }
    }

    for rule in &import_data.rules {
        if existing.rules.len() >= MAX_RULES {
            break;
        }
        if !existing.rules.iter().any(|r| r.id == rule.id) {
            existing.rules.push(rule.clone());
            imported += 1;
        }
    }

    save_rules(app_data_dir, &existing)?;
    Ok(imported)
}

pub fn max_rules() -> usize {
    MAX_RULES
}

pub fn max_alerts() -> usize {
    MAX_ALERTS
}
