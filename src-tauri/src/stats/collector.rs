use std::collections::HashMap;
use crate::models::*;

const TIMELINE_WINDOW_SECS: u64 = 1;

pub struct StatsCollector {
    protocol_counts: HashMap<String, u64>,
    protocol_bytes: HashMap<String, u64>,
    timeline: HashMap<u64, TimelineEntry>,
    src_ip_counts: HashMap<String, u64>,
    dst_ip_counts: HashMap<String, u64>,
    port_counts: HashMap<u16, u64>,
    tcp_states: HashMap<String, u64>,
    total_packets: u64,
    total_bytes: u64,
    start_time: Option<u64>,
}

#[derive(Default)]
struct TimelineEntry {
    packets: u64,
    bytes: u64,
}

impl StatsCollector {
    pub fn new() -> Self {
        Self {
            protocol_counts: HashMap::new(),
            protocol_bytes: HashMap::new(),
            timeline: HashMap::new(),
            src_ip_counts: HashMap::new(),
            dst_ip_counts: HashMap::new(),
            port_counts: HashMap::new(),
            tcp_states: HashMap::new(),
            total_packets: 0,
            total_bytes: 0,
            start_time: None,
        }
    }

    pub fn record_packet(&mut self, meta: &PacketMetadata) {
        if self.start_time.is_none() {
            self.start_time = Some(meta.timestamp_secs);
        }

        self.total_packets += 1;
        self.total_bytes += meta.length as u64;

        let proto_name = meta.protocol.as_str().to_string();
        *self.protocol_counts.entry(proto_name.clone()).or_insert(0) += 1;
        *self.protocol_bytes.entry(proto_name).or_insert(0) += meta.length as u64;

        let bucket = meta.timestamp_secs / TIMELINE_WINDOW_SECS;
        let entry = self.timeline.entry(bucket).or_default();
        entry.packets += 1;
        entry.bytes += meta.length as u64;

        *self.src_ip_counts.entry(meta.src_addr.clone()).or_insert(0) += 1;
        *self.dst_ip_counts.entry(meta.dst_addr.clone()).or_insert(0) += 1;

        if let Some(sp) = meta.src_port {
            *self.port_counts.entry(sp).or_insert(0) += 1;
        }
        if let Some(dp) = meta.dst_port {
            *self.port_counts.entry(dp).or_insert(0) += 1;
        }

        if meta.protocol == ProtocolType::TCP {
            let state = if meta.summary.contains("SYN") && !meta.summary.contains("ACK") {
                "SYN_SENT"
            } else if meta.summary.contains("SYN") && meta.summary.contains("ACK") {
                "SYN_RECEIVED"
            } else if meta.summary.contains("FIN") {
                "FIN_WAIT"
            } else if meta.summary.contains("RST") {
                "RESET"
            } else if meta.summary.contains("ACK") {
                "ESTABLISHED"
            } else {
                "OTHER"
            };
            *self.tcp_states.entry(state.to_string()).or_insert(0) += 1;
        }
    }

    pub fn get_snapshot(&self) -> StatsSnapshot {
        let mut protocol_counts: Vec<(String, u64)> = self.protocol_counts.iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        protocol_counts.sort_by(|a, b| b.1.cmp(&a.1));

        let mut protocol_bytes: Vec<(String, u64)> = self.protocol_bytes.iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        protocol_bytes.sort_by(|a, b| b.1.cmp(&a.1));

        let mut pps_timeline: Vec<(u64, u64)> = self.timeline.iter()
            .map(|(k, v)| (*k, v.packets))
            .collect();
        pps_timeline.sort_by_key(|(k, _)| *k);

        let mut bps_timeline: Vec<(u64, u64)> = self.timeline.iter()
            .map(|(k, v)| (*k, v.bytes))
            .collect();
        bps_timeline.sort_by_key(|(k, _)| *k);

        let mut top_src_ips: Vec<(String, u64)> = self.src_ip_counts.iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        top_src_ips.sort_by(|a, b| b.1.cmp(&a.1));
        top_src_ips.truncate(10);

        let mut top_dst_ips: Vec<(String, u64)> = self.dst_ip_counts.iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        top_dst_ips.sort_by(|a, b| b.1.cmp(&a.1));
        top_dst_ips.truncate(10);

        let mut top_ports: Vec<(u16, u64)> = self.port_counts.iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        top_ports.sort_by(|a, b| b.1.cmp(&a.1));
        top_ports.truncate(10);

        let tcp_states: Vec<(String, u64)> = self.tcp_states.iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();

        StatsSnapshot {
            protocol_counts,
            protocol_bytes,
            pps_timeline,
            bps_timeline,
            top_src_ips,
            top_dst_ips,
            top_ports,
            tcp_states,
        }
    }
}
