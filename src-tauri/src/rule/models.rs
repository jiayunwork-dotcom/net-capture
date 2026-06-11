use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    High,
    Medium,
    Low,
}

impl Priority {
    pub fn as_str(&self) -> &str {
        match self {
            Priority::High => "high",
            Priority::Medium => "medium",
            Priority::Low => "low",
        }
    }

    pub fn order(&self) -> u8 {
        match self {
            Priority::High => 0,
            Priority::Medium => 1,
            Priority::Low => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConditionNode {
    And { children: Vec<ConditionNode> },
    Or { children: Vec<ConditionNode> },
    Not { child: Box<ConditionNode> },
    ProtocolMatch { protocol: String },
    IpMatch {
        field: IpField,
        cidr: String,
    },
    PortRange {
        field: PortField,
        min: u16,
        max: u16,
    },
    PacketLength {
        operator: LengthOperator,
        value: u32,
    },
    TcpFlags {
        flags: Vec<TcpFlag>,
        mode: FlagMatchMode,
    },
    PayloadKeyword {
        pattern: String,
        #[serde(skip)]
        compiled: Option<regex::Regex>,
    },
    RateLimit {
        window_secs: u32,
        threshold: u32,
        src_ip: bool,
    },
    DnsBlacklist { domains: Vec<String> },
}

impl PartialEq for ConditionNode {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ConditionNode::And { children: a }, ConditionNode::And { children: b }) => a == b,
            (ConditionNode::Or { children: a }, ConditionNode::Or { children: b }) => a == b,
            (ConditionNode::Not { child: a }, ConditionNode::Not { child: b }) => a == b,
            (ConditionNode::ProtocolMatch { protocol: a }, ConditionNode::ProtocolMatch { protocol: b }) => a == b,
            (ConditionNode::IpMatch { field: fa, cidr: ca }, ConditionNode::IpMatch { field: fb, cidr: cb }) => fa == fb && ca == cb,
            (ConditionNode::PortRange { field: fa, min: ma, max: xa }, ConditionNode::PortRange { field: fb, min: mb, max: xb }) => fa == fb && ma == mb && xa == xb,
            (ConditionNode::PacketLength { operator: oa, value: va }, ConditionNode::PacketLength { operator: ob, value: vb }) => oa == ob && va == vb,
            (ConditionNode::TcpFlags { flags: fa, mode: ma }, ConditionNode::TcpFlags { flags: fb, mode: mb }) => fa == fb && ma == mb,
            (ConditionNode::PayloadKeyword { pattern: pa, .. }, ConditionNode::PayloadKeyword { pattern: pb, .. }) => pa == pb,
            (ConditionNode::RateLimit { window_secs: wa, threshold: ta, src_ip: sa }, ConditionNode::RateLimit { window_secs: wb, threshold: tb, src_ip: sb }) => wa == wb && ta == tb && sa == sb,
            (ConditionNode::DnsBlacklist { domains: a }, ConditionNode::DnsBlacklist { domains: b }) => a == b,
            _ => false,
        }
    }
}

impl Eq for ConditionNode {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpField {
    Src,
    Dst,
    Either,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortField {
    Src,
    Dst,
    Either,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LengthOperator {
    GreaterThan,
    LessThan,
    Equal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TcpFlag {
    SYN,
    ACK,
    FIN,
    RST,
    PSH,
    URG,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagMatchMode {
    All,
    Any,
    Exact,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertActions {
    pub system_notification: bool,
    pub sound: bool,
    pub auto_mark: bool,
    pub mark_level: Option<String>,
    pub auto_export: bool,
    pub export_path: Option<String>,
}

impl Default for AlertActions {
    fn default() -> Self {
        Self {
            system_notification: false,
            sound: false,
            auto_mark: false,
            mark_level: None,
            auto_export: false,
            export_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub priority: Priority,
    pub enabled: bool,
    pub condition: ConditionNode,
    pub expression: String,
    pub actions: AlertActions,
    pub group: Option<String>,
    pub description: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub priority: Priority,
    pub packet_no: u64,
    pub timestamp_secs: u64,
    pub timestamp_micros: u32,
    pub match_summary: String,
    pub src_addr: String,
    pub dst_addr: String,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleGroup {
    pub id: String,
    pub name: String,
    pub order: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RulesFile {
    pub version: String,
    pub groups: Vec<RuleGroup>,
    pub rules: Vec<DetectionRule>,
}

impl Default for RulesFile {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            groups: Vec::new(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EvalContext<'a> {
    pub packet_meta: &'a crate::models::PacketMetadata,
    pub raw_data: &'a [u8],
    pub parsed_layers: Option<&'a crate::models::PacketDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseError {
    pub message: String,
    pub position: Option<usize>,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(pos) = self.position {
            write!(f, "{} at position {}", self.message, pos)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for ParseError {}
