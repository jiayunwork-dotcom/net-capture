use std::collections::HashMap;
use crate::models::*;
use crate::stream::reassembly::TcpReassembler;

const MAX_ACTIVE_SESSIONS: usize = 10_000;
const MAX_TIMELINE_PACKETS: usize = 5000;

#[derive(Debug)]
struct SessionEntry {
    info: SessionInfo,
    tcp_reassembler: Option<TcpReassembler>,
    packet_nos: Vec<u64>,
    client_addr: String,
    client_port: u16,
}

pub struct SessionTracker {
    sessions: HashMap<String, SessionEntry>,
    session_order: Vec<String>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            session_order: Vec::new(),
        }
    }

    pub fn process_packet(&mut self, meta: &PacketMetadata, raw: &RawPacket) {
        let key = Self::make_session_key(meta);
        let reverse_key = Self::make_reverse_session_key(meta);

        let existing_key = if self.sessions.contains_key(&key) {
            Some(key.clone())
        } else if self.sessions.contains_key(&reverse_key) {
            Some(reverse_key.clone())
        } else {
            None
        };

        if let Some(ek) = existing_key {
            if let Some(entry) = self.sessions.get_mut(&ek) {
                entry.info.packet_count += 1;
                entry.info.byte_count += meta.length as u64;
                let ts_diff = (meta.timestamp_secs as i64 - entry.info.duration_ms as i64 / 1000).max(0);
                entry.info.duration_ms = (entry.info.duration_ms as i64 / 1000 + ts_diff) as u64 * 1000;
                entry.info.last_packet_no = meta.no;
                entry.packet_nos.push(meta.no);

                if meta.protocol == ProtocolType::TCP {
                    Self::update_tcp_state(&mut entry.info, meta);
                    if let Some(reassembler) = &mut entry.tcp_reassembler {
                        reassembler.add_segment(meta, raw);
                    }
                }
            }
        } else {
            if self.sessions.len() >= MAX_ACTIVE_SESSIONS {
                if let Some(oldest_key) = self.session_order.first().cloned() {
                    if let Some(mut entry) = self.sessions.remove(&oldest_key) {
                        entry.info.state = SessionState::Expired;
                    }
                    self.session_order.remove(0);
                }
            }

            let reassembler = if meta.protocol == ProtocolType::TCP {
                Some(TcpReassembler::new(meta.src_addr.clone(), meta.src_port.unwrap_or(0), meta.dst_addr.clone(), meta.dst_port.unwrap_or(0)))
            } else {
                None
            };

            let state = if meta.protocol == ProtocolType::TCP {
                SessionState::Active
            } else {
                SessionState::Active
            };

            let info = SessionInfo {
                id: key.clone(),
                src_addr: meta.src_addr.clone(),
                src_port: meta.src_port.unwrap_or(0),
                dst_addr: meta.dst_addr.clone(),
                dst_port: meta.dst_port.unwrap_or(0),
                protocol: meta.protocol,
                packet_count: 1,
                byte_count: meta.length as u64,
                duration_ms: 0,
                state,
                first_packet_no: meta.no,
                last_packet_no: meta.no,
            };

            self.sessions.insert(key.clone(), SessionEntry {
                info,
                tcp_reassembler: reassembler,
                packet_nos: vec![meta.no],
                client_addr: meta.src_addr.clone(),
                client_port: meta.src_port.unwrap_or(0),
            });
            self.session_order.push(key);
        }
    }

    fn update_tcp_state(info: &mut SessionInfo, meta: &PacketMetadata) {
        let summary = &meta.summary;
        if summary.contains("FIN") {
            info.state = SessionState::Closed;
        } else if summary.contains("RST") {
            info.state = SessionState::Closed;
        }
    }

    fn make_session_key(meta: &PacketMetadata) -> String {
        format!(
            "{}:{}->{}:{}:{:?}",
            meta.src_addr,
            meta.src_port.unwrap_or(0),
            meta.dst_addr,
            meta.dst_port.unwrap_or(0),
            meta.protocol
        )
    }

    fn make_reverse_session_key(meta: &PacketMetadata) -> String {
        format!(
            "{}:{}->{}:{}:{:?}",
            meta.dst_addr,
            meta.dst_port.unwrap_or(0),
            meta.src_addr,
            meta.src_port.unwrap_or(0),
            meta.protocol
        )
    }

    pub fn get_sessions(&self) -> Vec<SessionInfo> {
        self.sessions.values().map(|e| e.info.clone()).collect()
    }

    pub fn get_tcp_stream(&mut self, session_id: &str) -> Option<TcpStreamData> {
        let entry = self.sessions.get_mut(session_id)?;
        let reassembler = entry.tcp_reassembler.as_mut()?;
        Some(reassembler.reassemble())
    }

    pub fn get_session_for_packet(&self, meta: &PacketMetadata) -> Option<SessionInfo> {
        let key = Self::make_session_key(meta);
        if let Some(entry) = self.sessions.get(&key) {
            return Some(entry.info.clone());
        }
        let reverse_key = Self::make_reverse_session_key(meta);
        self.sessions.get(&reverse_key).map(|e| e.info.clone())
    }

    pub fn get_session_packet_nos(&self, session_id: &str) -> Option<Vec<u64>> {
        self.sessions.get(session_id).map(|e| e.packet_nos.clone())
    }

    pub fn get_session_client_info(&self, session_id: &str) -> Option<(String, u16, String, u16)> {
        let entry = self.sessions.get(session_id)?;
        Some((
            entry.client_addr.clone(),
            entry.client_port,
            entry.info.dst_addr.clone(),
            entry.info.dst_port,
        ))
    }
}
