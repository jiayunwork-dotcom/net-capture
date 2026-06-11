use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use super::models::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttackPatternsFile {
    version: String,
    builtin_patterns: Vec<AttackPattern>,
    custom_patterns: Vec<AttackPattern>,
}

impl Default for AttackPatternsFile {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            builtin_patterns: builtin_patterns(),
            custom_patterns: Vec::new(),
        }
    }
}

fn builtin_patterns() -> Vec<AttackPattern> {
    let now = current_timestamp_secs();
    vec![
        AttackPattern {
            id: "builtin_port_scan".to_string(),
            name: "TCP端口扫描".to_string(),
            category: AttackCategory::PortScan,
            description: "模拟从单一源IP向多个目标端口发送SYN包的端口扫描行为".to_string(),
            params: AttackPatternParams {
                target_port_min: 1,
                target_port_max: 1000,
                source_port_min: 40000,
                source_port_max: 60000,
                packet_count: 500,
                packets_per_second: 100,
                protocol: "TCP".to_string(),
                tcp_flags: Some(vec!["SYN".to_string()]),
                random_source_ip: false,
                ..Default::default()
            },
            is_builtin: true,
            created_at: now,
            updated_at: now,
        },
        AttackPattern {
            id: "builtin_syn_flood".to_string(),
            name: "SYN洪泛攻击".to_string(),
            category: AttackCategory::SynFlood,
            description: "模拟大量伪造源IP的SYN包，目标为同一端口".to_string(),
            params: AttackPatternParams {
                target_port_min: 80,
                target_port_max: 80,
                packet_count: 2000,
                packets_per_second: 500,
                protocol: "TCP".to_string(),
                tcp_flags: Some(vec!["SYN".to_string()]),
                random_source_ip: true,
                ..Default::default()
            },
            is_builtin: true,
            created_at: now,
            updated_at: now,
        },
        AttackPattern {
            id: "builtin_dns_amp".to_string(),
            name: "DNS放大攻击".to_string(),
            category: AttackCategory::DnsAmplification,
            description: "模拟向DNS服务器发送大量ANY查询请求".to_string(),
            params: AttackPatternParams {
                target_port_min: 53,
                target_port_max: 53,
                packet_count: 500,
                packets_per_second: 100,
                protocol: "UDP".to_string(),
                dns_domain: Some("example.com".to_string()),
                random_source_ip: true,
                ..Default::default()
            },
            is_builtin: true,
            created_at: now,
            updated_at: now,
        },
        AttackPattern {
            id: "builtin_brute_force_ssh".to_string(),
            name: "SSH暴力破解".to_string(),
            category: AttackCategory::BruteForce,
            description: "模拟对SSH端口(22)的高频连接尝试".to_string(),
            params: AttackPatternParams {
                target_port_min: 22,
                target_port_max: 22,
                packet_count: 300,
                packets_per_second: 5,
                protocol: "TCP".to_string(),
                tcp_flags: Some(vec!["SYN".to_string()]),
                random_source_ip: false,
                ..Default::default()
            },
            is_builtin: true,
            created_at: now,
            updated_at: now,
        },
        AttackPattern {
            id: "builtin_http_flood".to_string(),
            name: "HTTP洪泛攻击".to_string(),
            category: AttackCategory::HttpFlood,
            description: "模拟大量HTTP GET请求".to_string(),
            params: AttackPatternParams {
                target_port_min: 80,
                target_port_max: 80,
                packet_count: 1000,
                packets_per_second: 200,
                protocol: "TCP".to_string(),
                http_method: Some("GET".to_string()),
                http_path: Some("/".to_string()),
                random_source_ip: true,
                ..Default::default()
            },
            is_builtin: true,
            created_at: now,
            updated_at: now,
        },
        AttackPattern {
            id: "builtin_udp_flood".to_string(),
            name: "UDP洪泛攻击".to_string(),
            category: AttackCategory::UdpFlood,
            description: "模拟大量UDP数据包攻击".to_string(),
            params: AttackPatternParams {
                target_port_min: 5000,
                target_port_max: 6000,
                packet_count: 1500,
                packets_per_second: 300,
                protocol: "UDP".to_string(),
                random_source_ip: true,
                ..Default::default()
            },
            is_builtin: true,
            created_at: now,
            updated_at: now,
        },
        AttackPattern {
            id: "builtin_icmp_flood".to_string(),
            name: "ICMP洪泛攻击(Ping of Death)".to_string(),
            category: AttackCategory::IcmpFlood,
            description: "模拟大量ICMP Echo请求".to_string(),
            params: AttackPatternParams {
                packet_count: 800,
                packets_per_second: 200,
                protocol: "ICMP".to_string(),
                random_source_ip: true,
                ..Default::default()
            },
            is_builtin: true,
            created_at: now,
            updated_at: now,
        },
    ]
}

fn current_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct AttackPatternManager {
    file_path: Option<PathBuf>,
    builtin_patterns: Vec<AttackPattern>,
    custom_patterns: Vec<AttackPattern>,
}

impl AttackPatternManager {
    pub fn new() -> Self {
        Self {
            file_path: None,
            builtin_patterns: builtin_patterns(),
            custom_patterns: Vec::new(),
        }
    }

    pub fn set_file_path(&mut self, path: PathBuf) {
        self.file_path = Some(path);
    }

    pub fn load_from_disk(&mut self) -> Result<(), String> {
        if let Some(ref path) = self.file_path {
            if path.exists() {
                let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
                let file: AttackPatternsFile = serde_json::from_str(&content).unwrap_or_default();
                if !file.builtin_patterns.is_empty() {
                    self.builtin_patterns = file.builtin_patterns;
                }
                self.custom_patterns = file.custom_patterns;
            }
        }
        Ok(())
    }

    pub fn save_to_disk(&self) -> Result<(), String> {
        if let Some(ref path) = self.file_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let file = AttackPatternsFile {
                version: "1.0".to_string(),
                builtin_patterns: self.builtin_patterns.clone(),
                custom_patterns: self.custom_patterns.clone(),
            };
            let content = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?;
            std::fs::write(path, content).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn get_all_patterns(&self) -> Vec<AttackPattern> {
        let mut all = self.builtin_patterns.clone();
        all.extend(self.custom_patterns.clone());
        all
    }

    pub fn get_patterns_by_category(&self, category: &AttackCategory) -> Vec<AttackPattern> {
        self.get_all_patterns()
            .into_iter()
            .filter(|p| std::mem::discriminant(&p.category) == std::mem::discriminant(category))
            .collect()
    }

    pub fn get_pattern(&self, id: &str) -> Option<AttackPattern> {
        self.get_all_patterns().into_iter().find(|p| p.id == id)
    }

    pub fn add_custom_pattern(&mut self, mut pattern: AttackPattern) -> Result<(), String> {
        if self.get_all_patterns().iter().any(|p| p.id == pattern.id) {
            return Err("特征ID已存在".to_string());
        }
        let now = current_timestamp_secs();
        pattern.is_builtin = false;
        pattern.created_at = now;
        pattern.updated_at = now;
        self.custom_patterns.push(pattern);
        self.save_to_disk()
    }

    pub fn update_custom_pattern(&mut self, mut pattern: AttackPattern) -> Result<(), String> {
        if let Some(pos) = self.custom_patterns.iter().position(|p| p.id == pattern.id) {
            pattern.is_builtin = false;
            pattern.updated_at = current_timestamp_secs();
            pattern.created_at = self.custom_patterns[pos].created_at;
            self.custom_patterns[pos] = pattern;
            self.save_to_disk()
        } else {
            Err("自定义特征不存在".to_string())
        }
    }

    pub fn delete_custom_pattern(&mut self, id: &str) -> Result<(), String> {
        if self.builtin_patterns.iter().any(|p| p.id == id) {
            return Err("内置特征不可删除".to_string());
        }
        let before = self.custom_patterns.len();
        self.custom_patterns.retain(|p| p.id != id);
        if self.custom_patterns.len() == before {
            return Err("特征不存在".to_string());
        }
        self.save_to_disk()
    }
}

impl Default for AttackPatternManager {
    fn default() -> Self {
        Self::new()
    }
}
