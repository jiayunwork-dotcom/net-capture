use std::collections::HashMap;
use std::net::IpAddr;
use super::models::*;

pub struct BanListManager {
    entries: HashMap<String, BanEntry>,
    file_path: Option<std::path::PathBuf>,
}

impl BanListManager {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
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
        self.save_to_disk()
    }

    pub fn cleanup_expired(&mut self) -> Result<usize, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let before = self.entries.len();
        self.entries.retain(|_, entry| !entry.is_expired(now));
        let removed = before - self.entries.len();
        if removed > 0 {
            self.save_to_disk()?;
        }
        Ok(removed)
    }

    pub fn clear_all(&mut self) -> Result<(), String> {
        self.entries.clear();
        self.save_to_disk()
    }
}

impl Default for BanListManager {
    fn default() -> Self {
        Self::new()
    }
}
