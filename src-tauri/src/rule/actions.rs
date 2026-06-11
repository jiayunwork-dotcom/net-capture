use std::sync::Arc;
use parking_lot::Mutex;
use tauri::Manager;
use crate::models::{MarkLevel, RawPacket};
use super::models::*;

pub struct AlertActionExecutor {
    mark_engine: Option<Arc<Mutex<crate::capture::CaptureEngine>>>,
    export_paths: std::collections::HashMap<String, String>,
    app_handle: Option<tauri::AppHandle>,
    last_notification_secs: std::sync::atomic::AtomicU64,
}

impl AlertActionExecutor {
    pub fn new() -> Self {
        Self {
            mark_engine: None,
            export_paths: std::collections::HashMap::new(),
            app_handle: None,
            last_notification_secs: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn set_mark_engine(&mut self, engine: Arc<Mutex<crate::capture::CaptureEngine>>) {
        self.mark_engine = Some(engine);
    }

    pub fn set_app_handle(&mut self, handle: tauri::AppHandle) {
        self.app_handle = Some(handle);
    }

    pub fn execute_actions(
        &self,
        rule: &DetectionRule,
        packet_no: u64,
        raw_packet: Option<&RawPacket>,
    ) -> Vec<String> {
        let mut executed = Vec::new();

        if rule.actions.system_notification {
            if self.send_system_notification(rule) {
                executed.push("system_notification".to_string());
            }
        }

        if rule.actions.sound {
            self.play_alert_sound(rule);
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

    fn send_system_notification(&self, rule: &DetectionRule) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let last = self.last_notification_secs.load(std::sync::atomic::Ordering::Relaxed);
        if now.saturating_sub(last) < 3 {
            return false;
        }
        self.last_notification_secs.store(now, std::sync::atomic::Ordering::Relaxed);

        if let Some(ref handle) = self.app_handle {
            let priority_label = match rule.priority {
                Priority::High => "🔴 高优先级",
                Priority::Medium => "🟠 中优先级",
                Priority::Low => "🟡 低优先级",
            };
            let title = format!("NetCapture 告警 - {}", priority_label);
            let body = format!("规则「{}」触发", rule.name);

            let notification = tauri::api::notification::Notification::new(handle.config().tauri.bundle.identifier.clone())
                .title(&title)
                .body(&body);

            match notification.show() {
                Ok(_) => true,
                Err(e) => {
                    eprintln!("系统通知发送失败: {:?}", e);
                    false
                }
            }
        } else {
            false
        }
    }

    fn play_alert_sound(&self, rule: &DetectionRule) {
        if let Some(ref handle) = self.app_handle {
            let priority_label = match rule.priority {
                Priority::High => "high",
                Priority::Medium => "medium",
                Priority::Low => "low",
            };
            let payload = serde_json::json!({
                "rule_name": rule.name,
                "priority": priority_label,
            });
            let _ = handle.emit_all("rule-alert-sound", payload);
        }
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
    use std::io::Write;

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
