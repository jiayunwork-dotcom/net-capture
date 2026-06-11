use serde::{Deserialize, Serialize};
use crate::rule::models::ResponseLogEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatchRecord {
    pub rule_id: String,
    pub rule_name: String,
    pub trigger_count: u64,
    pub first_packet_no: u64,
    pub first_timestamp_secs: u64,
    pub first_timestamp_micros: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySessionResult {
    pub session_id: String,
    pub session_label: String,
    pub total_packets: u64,
    pub processed_packets: u64,
    pub matched_rules: Vec<RuleMatchRecord>,
    pub response_logs: Vec<ResponseLogEntry>,
    pub started_at: u64,
    pub finished_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBatchSummary {
    pub session_count: u64,
    pub total_packets: u64,
    pub total_matched_rules: u64,
    pub total_response_actions: u64,
    pub sessions_with_hits: Vec<String>,
    pub sessions_without_hits: Vec<String>,
    pub per_session_results: Vec<ReplaySessionResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayProgress {
    pub session_id: String,
    pub current_packet: u64,
    pub total_packets: u64,
    pub is_batch: bool,
    pub current_session_index: u64,
    pub total_sessions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackCategory {
    PortScan,
    SynFlood,
    DnsAmplification,
    BruteForce,
    ArpSpoof,
    HttpFlood,
    UdpFlood,
    IcmpFlood,
    SlowLoris,
    Custom,
}

impl AttackCategory {
    pub fn as_str(&self) -> &str {
        match self {
            AttackCategory::PortScan => "端口扫描",
            AttackCategory::SynFlood => "SYN洪泛",
            AttackCategory::DnsAmplification => "DNS放大",
            AttackCategory::BruteForce => "暴力破解",
            AttackCategory::ArpSpoof => "ARP欺骗",
            AttackCategory::HttpFlood => "HTTP洪泛",
            AttackCategory::UdpFlood => "UDP洪泛",
            AttackCategory::IcmpFlood => "ICMP洪泛",
            AttackCategory::SlowLoris => "SlowLoris",
            AttackCategory::Custom => "自定义",
        }
    }

    pub fn all() -> Vec<AttackCategory> {
        vec![
            AttackCategory::PortScan,
            AttackCategory::SynFlood,
            AttackCategory::DnsAmplification,
            AttackCategory::BruteForce,
            AttackCategory::ArpSpoof,
            AttackCategory::HttpFlood,
            AttackCategory::UdpFlood,
            AttackCategory::IcmpFlood,
            AttackCategory::SlowLoris,
            AttackCategory::Custom,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPatternParams {
    pub target_ip: Option<String>,
    pub target_port_min: u16,
    pub target_port_max: u16,
    pub source_port_min: u16,
    pub source_port_max: u16,
    pub packet_count: u32,
    pub packets_per_second: u32,
    pub protocol: String,
    pub payload_pattern: Option<String>,
    pub random_source_ip: bool,
    pub tcp_flags: Option<Vec<String>>,
    pub dns_domain: Option<String>,
    pub http_method: Option<String>,
    pub http_path: Option<String>,
}

impl Default for AttackPatternParams {
    fn default() -> Self {
        Self {
            target_ip: None,
            target_port_min: 1,
            target_port_max: 1024,
            source_port_min: 1024,
            source_port_max: 65535,
            packet_count: 100,
            packets_per_second: 10,
            protocol: "TCP".to_string(),
            payload_pattern: None,
            random_source_ip: true,
            tcp_flags: None,
            dns_domain: None,
            http_method: None,
            http_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub id: String,
    pub name: String,
    pub category: AttackCategory,
    pub description: String,
    pub params: AttackPatternParams,
    #[serde(default)]
    pub is_builtin: bool,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEffectivenessItem {
    pub pattern_id: String,
    pub pattern_name: String,
    pub pattern_category: String,
    pub is_detected: bool,
    pub matched_rule_names: Vec<String>,
    pub response_triggered: bool,
    pub response_actions: Vec<String>,
    pub total_packets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEffectivenessReport {
    pub generated_at: u64,
    pub total_patterns: u64,
    pub detected_count: u64,
    pub undetected_count: u64,
    pub detection_rate: f64,
    pub items: Vec<RuleEffectivenessItem>,
}
