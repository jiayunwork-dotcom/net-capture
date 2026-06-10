use std::collections::BTreeMap;
use crate::models::*;

const GAP_THRESHOLD: usize = 64 * 1024;

#[derive(Debug)]
pub struct TcpReassembler {
    client_addr: String,
    client_port: u16,
    server_addr: String,
    server_port: u16,
    client_segments: BTreeMap<u32, Vec<u8>>,
    server_segments: BTreeMap<u32, Vec<u8>>,
    client_next_seq: Option<u32>,
    server_next_seq: Option<u32>,
}

impl TcpReassembler {
    pub fn new(client_addr: String, client_port: u16, server_addr: String, server_port: u16) -> Self {
        Self {
            client_addr,
            client_port,
            server_addr,
            server_port,
            client_segments: BTreeMap::new(),
            server_segments: BTreeMap::new(),
            client_next_seq: None,
            server_next_seq: None,
        }
    }

    pub fn add_segment(&mut self, meta: &PacketMetadata, raw: &RawPacket) {
        if meta.protocol != ProtocolType::TCP {
            return;
        }

        let is_client = meta.src_addr == self.client_addr && meta.src_port == Some(self.client_port);

        let payload = extract_tcp_payload(raw);
        if payload.is_empty() {
            if is_client {
                if self.client_next_seq.is_none() {
                    self.client_next_seq = Some(extract_seq_num(raw));
                }
            } else {
                if self.server_next_seq.is_none() {
                    self.server_next_seq = Some(extract_seq_num(raw));
                }
            }
            return;
        }

        let seq = extract_seq_num(raw);

        if is_client {
            if self.client_next_seq.is_none() {
                self.client_next_seq = Some(seq);
            }
            self.client_segments.insert(seq, payload.to_vec());
        } else {
            if self.server_next_seq.is_none() {
                self.server_next_seq = Some(seq);
            }
            self.server_segments.insert(seq, payload.to_vec());
        }
    }

    pub fn reassemble(&self) -> TcpStreamData {
        let client_data = self.reassemble_direction(&self.client_segments, self.client_next_seq);
        let server_data = self.reassemble_direction(&self.server_segments, self.server_next_seq);

        let has_gap = client_data.iter().any(|s| s.missing) || server_data.iter().any(|s| s.missing);
        let gap_info = if has_gap {
            Some("数据缺失".into())
        } else {
            None
        };

        TcpStreamData {
            session_id: format!("{}:{}->{}:{}", self.client_addr, self.client_port, self.server_addr, self.server_port),
            client_data,
            server_data,
            has_gap,
            gap_info,
        }
    }

    fn reassemble_direction(
        &self,
        segments: &BTreeMap<u32, Vec<u8>>,
        next_seq: Option<u32>,
    ) -> Vec<StreamSegment> {
        let mut result = Vec::new();
        if segments.is_empty() {
            return result;
        }

        let mut expected_seq = next_seq.unwrap_or_else(|| *segments.keys().next().unwrap());
        let mut prev_end: Option<u32> = None;

        for (&seq, data) in segments.iter() {
            let data_len = data.len() as u32;
            let seg_end = seq.wrapping_add(data_len);

            if prev_end.is_some() && seq.wrapping_sub(prev_end.unwrap()) as usize > GAP_THRESHOLD {
                result.push(StreamSegment {
                    seq_start: prev_end.unwrap(),
                    seq_end: seq,
                    data: Vec::new(),
                    is_retransmission: false,
                    missing: true,
                });
            }

            if let Some(pe) = prev_end {
                if seq < pe {
                    result.push(StreamSegment {
                        seq_start: seq,
                        seq_end: seg_end,
                        data: data.clone(),
                        is_retransmission: true,
                        missing: false,
                    });
                    continue;
                }
            }

            let missing = if let Some(_es) = next_seq {
                seq > expected_seq
            } else {
                false
            };

            result.push(StreamSegment {
                seq_start: seq,
                seq_end: seg_end,
                data: data.clone(),
                is_retransmission: false,
                missing,
            });

            prev_end = Some(seg_end);
            expected_seq = seg_end;
        }

        result
    }
}

fn extract_tcp_payload(raw: &RawPacket) -> &[u8] {
    if raw.data.len() < 14 {
        return &[];
    }
    let ether_type = u16::from_be_bytes([raw.data[12], raw.data[13]]);

    let ip_offset = if ether_type == 0x8100 {
        18
    } else {
        14
    };

    if raw.data.len() < ip_offset + 20 {
        return &[];
    }

    let ihl = ((raw.data[ip_offset] & 0x0F) as usize) * 4;
    let total_len = u16::from_be_bytes([raw.data[ip_offset + 2], raw.data[ip_offset + 3]]) as usize;

    if raw.data.len() < ip_offset + ihl {
        return &[];
    }

    let protocol = raw.data[ip_offset + 9];
    if protocol != 6 {
        return &[];
    }

    let tcp_offset = ip_offset + ihl;
    if raw.data.len() < tcp_offset + 20 {
        return &[];
    }

    let data_offset = ((raw.data[tcp_offset + 12] >> 4) as usize) * 4;
    let payload_start = tcp_offset + data_offset;
    let payload_end = ip_offset + total_len;

    if payload_start >= raw.data.len() || payload_start >= payload_end {
        return &[];
    }

    let end = payload_end.min(raw.data.len());
    &raw.data[payload_start..end]
}

fn extract_seq_num(raw: &RawPacket) -> u32 {
    if raw.data.len() < 14 {
        return 0;
    }
    let ether_type = u16::from_be_bytes([raw.data[12], raw.data[13]]);
    let ip_offset = if ether_type == 0x8100 { 18 } else { 14 };

    if raw.data.len() < ip_offset + 20 {
        return 0;
    }

    let ihl = ((raw.data[ip_offset] & 0x0F) as usize) * 4;
    let tcp_offset = ip_offset + ihl;

    if raw.data.len() < tcp_offset + 8 {
        return 0;
    }

    u32::from_be_bytes([
        raw.data[tcp_offset + 4],
        raw.data[tcp_offset + 5],
        raw.data[tcp_offset + 6],
        raw.data[tcp_offset + 7],
    ])
}
