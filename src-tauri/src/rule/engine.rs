use std::net::IpAddr;
use cidr::IpCidr;
use regex::Regex;
use crate::models::{PacketMetadata, TcpFlags, DnsLayer, ProtocolType};
use super::models::*;
use super::rate_counter::RateCounterManager;

pub struct RuleEngine {
    rules: Vec<DetectionRule>,
    rate_counters: RateCounterManager,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            rate_counters: RateCounterManager::new(),
        }
    }

    pub fn set_rules(&mut self, mut rules: Vec<DetectionRule>) {
        rules.sort_by_key(|r| r.priority.order());
        self.rules = rules;
    }

    pub fn add_rule(&mut self, rule: DetectionRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority.order());
    }

    pub fn evaluate_packet(
        &mut self,
        meta: &PacketMetadata,
        raw_data: &[u8],
        parsed_layers: Option<&crate::models::PacketDetail>,
    ) -> Vec<DetectionRule> {
        let mut matched = Vec::new();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            let ctx = EvalContext {
                packet_meta: meta,
                raw_data,
                parsed_layers,
            };

            if evaluate_condition(&rule.condition, &ctx, &mut self.rate_counters) {
                matched.push(rule.clone());
            }
        }

        matched
    }

    pub fn clear_rate_counters(&mut self) {
        self.rate_counters = RateCounterManager::new();
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

pub fn evaluate_condition(
    condition: &ConditionNode,
    ctx: &EvalContext,
    rate_counters: &mut RateCounterManager,
) -> bool {
    match condition {
        ConditionNode::And { children } => {
            children.iter().all(|c| evaluate_condition(c, ctx, rate_counters))
        }
        ConditionNode::Or { children } => {
            children.iter().any(|c| evaluate_condition(c, ctx, rate_counters))
        }
        ConditionNode::Not { child } => {
            !evaluate_condition(child, ctx, rate_counters)
        }
        ConditionNode::ProtocolMatch { protocol } => {
            check_protocol_match(ctx.packet_meta, protocol)
        }
        ConditionNode::IpMatch { field, cidr } => {
            check_ip_match(ctx.packet_meta, field, cidr)
        }
        ConditionNode::PortRange { field, min, max } => {
            check_port_range(ctx.packet_meta, field, *min, *max)
        }
        ConditionNode::PacketLength { operator, value } => {
            check_packet_length(ctx.packet_meta.length, operator, *value)
        }
        ConditionNode::TcpFlags { flags, mode } => {
            check_tcp_flags(ctx.packet_meta, flags, mode)
        }
        ConditionNode::PayloadKeyword { pattern, compiled } => {
            check_payload_keyword(ctx.raw_data, pattern, compiled.as_ref())
        }
        ConditionNode::RateLimit { window_secs, threshold, src_ip } => {
            check_rate_limit(
                ctx.packet_meta,
                *window_secs,
                *threshold,
                *src_ip,
                rate_counters,
            )
        }
        ConditionNode::DnsBlacklist { domains } => {
            check_dns_blacklist(ctx.parsed_layers, domains)
        }
    }
}

fn check_protocol_match(meta: &PacketMetadata, protocol: &str) -> bool {
    let proto = protocol.to_lowercase();
    match proto.as_str() {
        "tcp" => matches!(meta.protocol, ProtocolType::TCP | ProtocolType::HTTP | ProtocolType::TLS),
        "udp" => matches!(meta.protocol, ProtocolType::UDP | ProtocolType::DNS),
        "http" => matches!(meta.protocol, ProtocolType::HTTP),
        "dns" => matches!(meta.protocol, ProtocolType::DNS),
        "tls" | "ssl" => matches!(meta.protocol, ProtocolType::TLS),
        "icmp" => matches!(meta.protocol, ProtocolType::ICMP),
        "arp" => matches!(meta.protocol, ProtocolType::ARP),
        "ip" | "ipv4" => matches!(meta.protocol, ProtocolType::IPv4),
        "ipv6" => matches!(meta.protocol, ProtocolType::IPv6),
        _ => meta.protocol.as_str().eq_ignore_ascii_case(protocol),
    }
}

fn check_ip_match(meta: &PacketMetadata, field: &IpField, cidr_str: &str) -> bool {
    let cidr = match cidr_str.parse::<IpCidr>() {
        Ok(c) => c,
        Err(_) => return false,
    };

    let check_addr = |addr: &str| -> bool {
        match addr.parse::<IpAddr>() {
            Ok(ip) => cidr.contains(&ip),
            Err(_) => false,
        }
    };

    match field {
        IpField::Src => check_addr(&meta.src_addr),
        IpField::Dst => check_addr(&meta.dst_addr),
        IpField::Either => check_addr(&meta.src_addr) || check_addr(&meta.dst_addr),
    }
}

fn check_port_range(meta: &PacketMetadata, field: &PortField, min: u16, max: u16) -> bool {
    let check_port = |port: Option<u16>| -> bool {
        match port {
            Some(p) => p >= min && p <= max,
            None => false,
        }
    };

    match field {
        PortField::Src => check_port(meta.src_port),
        PortField::Dst => check_port(meta.dst_port),
        PortField::Either => check_port(meta.src_port) || check_port(meta.dst_port),
    }
}

fn check_packet_length(length: u32, operator: &LengthOperator, value: u32) -> bool {
    match operator {
        LengthOperator::GreaterThan => length > value,
        LengthOperator::LessThan => length < value,
        LengthOperator::Equal => length == value,
    }
}

fn check_tcp_flags(meta: &PacketMetadata, expected_flags: &[TcpFlag], mode: &FlagMatchMode) -> bool {
    if !matches!(meta.protocol, ProtocolType::TCP | ProtocolType::HTTP | ProtocolType::TLS) {
        return false;
    }

    let actual_flags = match &meta.tcp_flags {
        Some(flags_str) => parse_tcp_flags_string(flags_str),
        None => return false,
    };

    match mode {
        FlagMatchMode::All => {
            expected_flags.iter().all(|f| actual_flags.contains(f))
        }
        FlagMatchMode::Any => {
            expected_flags.iter().any(|f| actual_flags.contains(f))
        }
        FlagMatchMode::Exact => {
            actual_flags.len() == expected_flags.len()
                && expected_flags.iter().all(|f| actual_flags.contains(f))
        }
        FlagMatchMode::None => {
            expected_flags.iter().all(|f| !actual_flags.contains(f))
        }
    }
}

fn parse_tcp_flags_string(flags_str: &str) -> Vec<TcpFlag> {
    let mut flags = Vec::new();
    for part in flags_str.split(", ") {
        match part.trim().to_uppercase().as_str() {
            "SYN" => flags.push(TcpFlag::SYN),
            "ACK" => flags.push(TcpFlag::ACK),
            "FIN" => flags.push(TcpFlag::FIN),
            "RST" => flags.push(TcpFlag::RST),
            "PSH" => flags.push(TcpFlag::PSH),
            "URG" => flags.push(TcpFlag::URG),
            _ => {}
        }
    }
    flags
}

fn check_payload_keyword(raw_data: &[u8], pattern: &str, compiled: Option<&Regex>) -> bool {
    let re_owned;
    let re = match compiled {
        Some(r) => r,
        None => {
            re_owned = match Regex::new(pattern) {
                Ok(r) => r,
                Err(_) => return false,
            };
            &re_owned
        }
    };

    if let Ok(text) = std::str::from_utf8(raw_data) {
        re.is_match(text)
    } else {
        let lossy = String::from_utf8_lossy(raw_data);
        re.is_match(&lossy)
    }
}

fn check_rate_limit(
    meta: &PacketMetadata,
    window_secs: u32,
    threshold: u32,
    src_ip: bool,
    rate_counters: &mut RateCounterManager,
) -> bool {
    let ip = if src_ip {
        meta.src_addr.clone()
    } else {
        meta.dst_addr.clone()
    };

    let ts = meta.timestamp_secs;

    rate_counters.record_packet(&ip, ts);
    rate_counters.check_rate(window_secs, threshold, src_ip, &ip, ts)
}

fn check_dns_blacklist(parsed_layers: Option<&crate::models::PacketDetail>, blacklist: &[String]) -> bool {
    let detail = match parsed_layers {
        Some(d) => d,
        None => return false,
    };

    for layer in &detail.layers {
        if layer.protocol == "DNS" {
            for field in &layer.fields {
                if field.name == "Domain" || field.name == "Query Name" {
                    let domain = field.value.to_lowercase();
                    for blacklisted in blacklist {
                        let bl = blacklisted.to_lowercase();
                        if domain == bl || domain.ends_with(&format!(".{}", bl)) {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

pub fn compile_regex_in_rule(rule: &mut DetectionRule) -> Result<(), String> {
    compile_regex_in_node(&mut rule.condition)?;
    Ok(())
}

fn compile_regex_in_node(node: &mut ConditionNode) -> Result<(), String> {
    match node {
        ConditionNode::And { children } | ConditionNode::Or { children } => {
            for child in children {
                compile_regex_in_node(child)?;
            }
        }
        ConditionNode::Not { child } => {
            compile_regex_in_node(child)?;
        }
        ConditionNode::PayloadKeyword { pattern, compiled } => {
            let re = Regex::new(pattern).map_err(|e| format!("正则表达式无效: {}", e))?;
            *compiled = Some(re);
        }
        _ => {}
    }
    Ok(())
}
