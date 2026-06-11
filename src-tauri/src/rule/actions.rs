use std::sync::Arc;
use parking_lot::Mutex;
use crate::models::{MarkLevel, RawPacket};
use crate::pcap_io::export as pcap_export;
use super::models::*;

pub struct AlertActionExecutor {
    mark_engine: Option<Arc<Mutex<crate::capture::CaptureEngine>>>,
    export_paths: std::collections::HashMap<String, String>,
}

impl AlertActionExecutor {
    pub fn new() -> Self {
        Self {
            mark_engine: None,
            export_paths: std::collections::HashMap::new(),
        }
    }

    pub fn set_mark_engine(&mut self, engine: Arc<Mutex<crate::capture::CaptureEngine>>) {
        self.mark_engine = Some(engine);
    }

    pub fn execute_actions(
        &self,
        rule: &DetectionRule,
        packet_no: u64,
        raw_packet: Option<&RawPacket>,
    ) -> Vec<String> {
        let mut executed = Vec::new();

        if rule.actions.system_notification {
            executed.push("system_notification".to_string());
        }

        if rule.actions.sound {
            executed.push("sound".to_string());
        }

        if rule.actions.auto_mark {
            if let Some(ref engine) = self.mark_engine {
                if let Some(ref level_str) = rule.actions.mark_level {
                    if let Ok(level) = parse_mark_level(level_str) {
                        let mut eng = engine.lock();
                        let _ = eng.set_mark(packet_no, level, format!("规则触发: {}", rule.name));
                        executed.push("auto_mark".to_string());
                    }
                }
            }
        }

        if rule.actions.auto_export {
            if let Some(ref path) = rule.actions.export_path {
                if let Some(raw) = raw_packet {
                    let _ = append_to_pcap(path, raw);
                    executed.push("auto_export".to_string());
                }
            }
        }

        executed
    }
}

impl Default for AlertActionExecutor {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_mark_level(s: &str) -> Result<MarkLevel, String> {
    match s.to_lowercase().as_str() {
        "starred" | "star" => Ok(MarkLevel::Starred),
        "warning" | "warn" => Ok(MarkLevel::Warning),
        "important" | "critical" => Ok(MarkLevel::Important),
        _ => Err(format!("Invalid mark level: {}", s)),
    }
}

fn append_to_pcap(path: &str, packet: &RawPacket) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::io::{Write, Seek, SeekFrom};

    let file_exists = std::path::Path::new(path).exists();

    if !file_exists {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(path)
            .map_err(|e| e.to_string())?;

        let header = pcap_global_header();
        file.write_all(&header).map_err(|e| e.to_string())?;
    }

    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;

    let record = pcap_record(packet);
    file.write_all(&record).map_err(|e| e.to_string())?;

    Ok(())
}

fn pcap_global_header() -> Vec<u8> {
    let mut header = Vec::with_capacity(24);
    header.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    header.extend_from_slice(&2u16.to_le_bytes());
    header.extend_from_slice(&4u16.to_le_bytes());
    header.extend_from_slice(&0i32.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&65535u32.to_le_bytes());
    header.extend_from_slice(&1u32.to_le_bytes());
    header
}

fn pcap_record(packet: &RawPacket) -> Vec<u8> {
    let mut record = Vec::with_capacity(16 + packet.data.len());
    record.extend_from_slice(&(packet.timestamp_secs as u32).to_le_bytes());
    record.extend_from_slice(&packet.timestamp_micros.to_le_bytes());
    record.extend_from_slice(&(packet.data.len() as u32).to_le_bytes());
    record.extend_from_slice(&(packet.data.len() as u32).to_le_bytes());
    record.extend_from_slice(&packet.data);
    record
}
