use std::collections::HashMap;
use std::net::IpAddr;
use chrono::TimeZone;
use super::models::*;

pub struct BanListManager {
    entries: HashMap<String, BanEntry>,
    related_alerts: HashMap<String, Vec<BanRelatedAlert>>,
    file_path: Option<std::path::PathBuf>,
}

impl BanListManager {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            related_alerts: HashMap::new(),
            file_path: None,
        }
    }

    pub fn set_file_path(&mut self, path: std::path::PathBuf) {
        self.file_path = Some(path);
        let _ = self.load_from_disk();
    }

    pub fn load_from_disk(&mut self) -> Result<(), String> {
        if let Some(ref path) = self.file_path {
            if path.exists() {
                let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
                let entries: Vec<BanEntry> = serde_json::from_str(&content).unwrap_or_default();
                self.entries.clear();
                for entry in entries {
                    self.entries.insert(entry.ip.clone(), entry);
                }
            }
        }
        Ok(())
    }

    pub fn save_to_disk(&self) -> Result<(), String> {
        if let Some(ref path) = self.file_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let entries: Vec<&BanEntry> = self.entries.values().collect();
            let content = serde_json::to_string_pretty(&entries).map_err(|e| e.to_string())?;
            std::fs::write(path, content).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn add_entry(&mut self, entry: BanEntry) -> Result<(), String> {
        self.entries.insert(entry.ip.clone(), entry);
        self.save_to_disk()
    }

    pub fn is_banned(&self, addr: &str) -> bool {
        if let Some(entry) = self.entries.get(addr) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            !entry.is_expired(now)
        } else {
            false
        }
    }

    pub fn check_ip_match(&self, src_addr: &str, dst_addr: &str) -> bool {
        self.is_banned(src_addr) || self.is_banned(dst_addr)
    }

    pub fn get_all_entries(&self) -> Vec<BanEntry> {
        self.entries.values().cloned().collect()
    }

    pub fn unban(&mut self, ip: &str) -> Result<(), String> {
        self.entries.remove(ip);
        self.related_alerts.remove(ip);
        self.save_to_disk()
    }

    pub fn cleanup_expired(&mut self) -> Result<usize, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let before = self.entries.len();
        let expired_ips: Vec<String> = self.entries
            .iter()
            .filter(|(_, entry)| entry.is_expired(now))
            .map(|(ip, _)| ip.clone())
            .collect();
        for ip in &expired_ips {
            self.entries.remove(ip);
            self.related_alerts.remove(ip);
        }
        let removed = before - self.entries.len();
        if removed > 0 {
            self.save_to_disk()?;
        }
        Ok(removed)
    }

    pub fn clear_all(&mut self) -> Result<(), String> {
        self.entries.clear();
        self.related_alerts.clear();
        self.save_to_disk()
    }

    pub fn record_related_alert(&mut self, ip: &str, alert: BanRelatedAlert) {
        if let Some(entry) = self.entries.get_mut(ip) {
            entry.related_alerts_count += 1;
        }
        self.related_alerts.entry(ip.to_string()).or_default().push(alert);
    }

    pub fn get_related_alerts(&self, ip: &str) -> Vec<BanRelatedAlert> {
        self.related_alerts.get(ip).cloned().unwrap_or_default()
    }

    pub fn export_csv(&self) -> Result<String, String> {
        let mut csv = String::from("IP,封禁时间,过期时间,关联规则名\n");
        for entry in self.entries.values() {
            let ban_time_str = format_timestamp(entry.ban_time);
            let expire_str = if entry.expire_minutes == 0 {
                "永久".to_string()
            } else {
                format_timestamp(entry.ban_time + entry.expire_minutes * 60)
            };
            csv.push_str(&format!("{},{},{},{}\n", entry.ip, ban_time_str, expire_str, entry.rule_name));
        }
        Ok(csv)
    }

    pub fn import_csv(&mut self, content: &str) -> Result<BanImportResult, String> {
        let mut added: u32 = 0;
        let mut updated: u32 = 0;
        let mut ignored: u32 = 0;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        for (line_num, line) in content.lines().enumerate() {
            if line_num == 0 && line.starts_with("IP") {
                continue;
            }
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() < 4 {
                ignored += 1;
                continue;
            }
            let ip = parts[0].trim().to_string();
            if ip.is_empty() {
                ignored += 1;
                continue;
            }
            if let Err(_) = ip.parse::<IpAddr>() {
                ignored += 1;
                continue;
            }

            let ban_time = parse_csv_timestamp(parts[1].trim()).unwrap_or(now);
            let expire_minutes = if parts[2].trim() == "永久" {
                0u64
            } else {
                let expire_ts = parse_csv_timestamp(parts[2].trim()).unwrap_or(0);
                if expire_ts > ban_time {
                    (expire_ts - ban_time) / 60
                } else {
                    60
                }
            };
            let rule_name = parts[3].trim().to_string();

            if let Some(existing) = self.entries.get_mut(&ip) {
                let existing_expire_ts = if existing.expire_minutes == 0 {
                    u64::MAX
                } else {
                    existing.ban_time + existing.expire_minutes * 60
                };
                let new_expire_ts = if expire_minutes == 0 {
                    u64::MAX
                } else {
                    ban_time + expire_minutes * 60
                };
                if new_expire_ts > existing_expire_ts {
                    existing.expire_minutes = expire_minutes;
                    existing.ban_time = ban_time;
                    existing.rule_name = rule_name;
                    updated += 1;
                } else {
                    ignored += 1;
                }
            } else {
                let entry = BanEntry {
                    ip: ip.clone(),
                    ban_time,
                    rule_id: format!("imported_{}", ip),
                    rule_name,
                    expire_minutes,
                    related_alerts_count: 0,
                };
                self.entries.insert(ip, entry);
                added += 1;
            }
        }

        self.save_to_disk()?;
        Ok(BanImportResult { added, updated, ignored })
    }
}

impl Default for BanListManager {
    fn default() -> Self {
        Self::new()
    }
}

fn format_timestamp(secs: u64) -> String {
    let dt = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
    let datetime: chrono::DateTime<chrono::Local> = dt.into();
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn parse_csv_timestamp(s: &str) -> Option<u64> {
    let naive = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").ok()?;
    let local = chrono::Local.from_local_datetime(&naive).single()?;
    Some(local.timestamp() as u64)
}
