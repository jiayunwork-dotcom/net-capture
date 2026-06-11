use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub friendly_name: String,
    pub ips: Vec<String>,
    pub mac: Option<String>,
    pub is_up: bool,
    pub is_loopback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketMetadata {
    pub no: u64,
    pub timestamp_secs: u64,
    pub timestamp_micros: u32,
    pub src_addr: String,
    pub src_port: Option<u16>,
    pub dst_addr: String,
    pub dst_port: Option<u16>,
    pub protocol: ProtocolType,
    pub length: u32,
    pub summary: String,
    pub ttl: Option<u8>,
    pub window_size: Option<u16>,
    pub tcp_flags: Option<String>,
    pub ip_id: Option<u16>,
    pub fragment_offset: Option<u16>,
}

impl PacketMetadata {
    pub fn timestamp_str(&self) -> String {
        chrono::DateTime::from_timestamp(self.timestamp_secs as i64, self.timestamp_micros * 1000)
            .map(|dt| dt.format("%H:%M:%S%.6f").to_string())
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolType {
    Ethernet,
    IPv4,
    IPv6,
    ARP,
    ICMP,
    TCP,
    UDP,
    HTTP,
    DNS,
    TLS,
    Unknown,
}

impl ProtocolType {
    pub fn bg_color(&self) -> &str {
        match self {
            ProtocolType::HTTP => "#c8e6c9",
            ProtocolType::DNS => "#bbdefb",
            ProtocolType::TCP => "#e0e0e0",
            ProtocolType::UDP => "#e1bee7",
            ProtocolType::TLS => "#ffe0b2",
            ProtocolType::ICMP => "#f8bbd0",
            ProtocolType::ARP => "#fff9c4",
            _ => "#ffffff",
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            ProtocolType::Ethernet => "ETH",
            ProtocolType::IPv4 => "IPv4",
            ProtocolType::IPv6 => "IPv6",
            ProtocolType::ARP => "ARP",
            ProtocolType::ICMP => "ICMP",
            ProtocolType::TCP => "TCP",
            ProtocolType::UDP => "UDP",
            ProtocolType::HTTP => "HTTP",
            ProtocolType::DNS => "DNS",
            ProtocolType::TLS => "TLS",
            ProtocolType::Unknown => "???",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketDetail {
    pub no: u64,
    pub layers: Vec<ProtocolLayer>,
    pub raw_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolLayer {
    pub protocol: String,
    pub fields: Vec<FieldEntry>,
    pub byte_range: (usize, usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldEntry {
    pub name: String,
    pub value: String,
    pub byte_range: (usize, usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetLayer {
    pub src_mac: String,
    pub dst_mac: String,
    pub ether_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLayer {
    pub version: u8,
    pub header_len: u8,
    pub ttl: u8,
    pub protocol: u8,
    pub src_ip: String,
    pub dst_ip: String,
    pub identification: u16,
    pub fragment_offset: u16,
    pub more_fragments: bool,
    pub dont_fragment: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpLayer {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

impl TcpFlags {
    pub fn from_bits(bits: u8) -> Self {
        Self {
            fin: bits & 0x01 != 0,
            syn: bits & 0x02 != 0,
            rst: bits & 0x04 != 0,
            psh: bits & 0x08 != 0,
            ack: bits & 0x10 != 0,
            urg: bits & 0x20 != 0,
        }
    }

    pub fn to_string_flags(&self) -> String {
        let mut flags = Vec::new();
        if self.fin { flags.push("FIN"); }
        if self.syn { flags.push("SYN"); }
        if self.rst { flags.push("RST"); }
        if self.psh { flags.push("PSH"); }
        if self.ack { flags.push("ACK"); }
        if self.urg { flags.push("URG"); }
        flags.join(", ")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpLayer {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpLayer {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub operation: u16,
    pub sender_mac: String,
    pub sender_ip: String,
    pub target_mac: String,
    pub target_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpLayer {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpLayer {
    pub is_request: bool,
    pub method: Option<String>,
    pub url: Option<String>,
    pub status_code: Option<u16>,
    pub status_text: Option<String>,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLayer {
    pub is_query: bool,
    pub query_type: Option<String>,
    pub domain: Option<String>,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: String,
    pub data: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsLayer {
    pub version: Option<String>,
    pub handshake_type: Option<String>,
    pub cipher_suites: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    pub protocol: ProtocolType,
    pub packet_count: u64,
    pub byte_count: u64,
    pub duration_ms: u64,
    pub state: SessionState,
    pub first_packet_no: u64,
    pub last_packet_no: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionState {
    Active,
    Closed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpStreamData {
    pub session_id: String,
    pub client_data: Vec<StreamSegment>,
    pub server_data: Vec<StreamSegment>,
    pub has_gap: bool,
    pub gap_info: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSegment {
    pub seq_start: u32,
    pub seq_end: u32,
    pub data: Vec<u8>,
    pub is_retransmission: bool,
    pub missing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStatus {
    pub is_capturing: bool,
    pub interface_name: Option<String>,
    pub packet_count: u64,
    pub dropped_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexDumpLine {
    pub offset: String,
    pub hex: Vec<String>,
    pub ascii: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsSnapshot {
    pub protocol_counts: Vec<(String, u64)>,
    pub protocol_bytes: Vec<(String, u64)>,
    pub pps_timeline: Vec<(u64, u64)>,
    pub bps_timeline: Vec<(u64, u64)>,
    pub top_src_ips: Vec<(String, u64)>,
    pub top_dst_ips: Vec<(String, u64)>,
    pub top_ports: Vec<(u16, u64)>,
    pub tcp_states: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPacket {
    pub timestamp_secs: u64,
    pub timestamp_micros: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MarkLevel {
    Starred,
    Warning,
    Important,
}

impl MarkLevel {
    pub fn as_str(&self) -> &str {
        match self {
            MarkLevel::Starred => "starred",
            MarkLevel::Warning => "warning",
            MarkLevel::Important => "important",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "starred" => Some(MarkLevel::Starred),
            "warning" => Some(MarkLevel::Warning),
            "important" => Some(MarkLevel::Important),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketMark {
    pub packet_no: u64,
    pub level: MarkLevel,
    pub comment: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSequenceEntry {
    pub packet_no: u64,
    pub timestamp_secs: u64,
    pub timestamp_micros: u32,
    pub direction: bool,
    pub seq_num: u32,
    pub ack_num: u32,
    pub payload_size: u32,
    pub flags: String,
    pub is_retransmission: bool,
    pub window_size: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpTimelineData {
    pub session_id: String,
    pub client_addr: String,
    pub client_port: u16,
    pub server_addr: String,
    pub server_port: u16,
    pub entries: Vec<TcpSequenceEntry>,
    pub is_truncated: bool,
    pub total_packets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureTemplate {
    pub name: String,
    pub interface_name: String,
    pub bpf_filter: String,
    pub promiscuous: bool,
    pub description: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}
