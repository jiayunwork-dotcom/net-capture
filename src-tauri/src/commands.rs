use tauri::State;
use crate::AppState;
use crate::capture::interface;
use crate::filter::display;
use crate::models::*;
use crate::pcap_io::export as pcap_export;
use crate::pcap_io::import as pcap_import;
use crate::protocol;
use crate::session::SessionTracker;
use crate::stats::StatsCollector;
use crate::tls::decryptor::TlsDecryptor;
use std::fs;
use std::path::PathBuf;
use etherparse::SlicedPacket;

#[tauri::command]
pub fn list_interfaces() -> Result<Vec<NetworkInterface>, String> {
    Ok(interface::list_interfaces())
}

#[tauri::command]
pub fn start_capture(
    state: State<'_, AppState>,
    interface_name: String,
    promiscuous: bool,
    bpf_filter: Option<String>,
) -> Result<(), String> {
    let mut engine = state.capture_engine.lock();
    let session_tracker = state.session_tracker.clone();
    let stats_collector = state.stats_collector.clone();
    engine.start_capture(
        &interface_name,
        promiscuous,
        bpf_filter.as_deref(),
        session_tracker,
        stats_collector,
    )
}

#[tauri::command]
pub fn stop_capture(state: State<'_, AppState>) -> Result<(), String> {
    let mut engine = state.capture_engine.lock();
    engine.stop_capture()
}

#[tauri::command]
pub fn get_capture_status(state: State<'_, AppState>) -> Result<CaptureStatus, String> {
    let engine = state.capture_engine.lock();
    Ok(engine.get_status())
}

#[tauri::command]
pub fn validate_bpf(state: State<'_, AppState>, filter: String) -> Result<(), String> {
    let engine = state.capture_engine.lock();
    engine.validate_bpf(&filter)
}

#[tauri::command]
pub fn drain_new_packets(state: State<'_, AppState>) -> Result<Vec<PacketMetadata>, String> {
    let mut engine = state.capture_engine.lock();
    Ok(engine.drain_new_packets())
}

#[tauri::command]
pub fn get_packet_detail(
    state: State<'_, AppState>,
    no: u64,
) -> Result<PacketDetail, String> {
    let raw_data = {
        let engine = state.capture_engine.lock();
        engine.get_raw_data(no)
            .ok_or_else(|| format!("Packet {} raw data not found", no))?
    };

    let raw = RawPacket {
        timestamp_secs: 0,
        timestamp_micros: 0,
        data: raw_data,
    };

    let mut detail = protocol::parse_packet_detail(&raw);
    detail.no = no;
    Ok(detail)
}

#[tauri::command]
pub fn get_hex_dump(state: State<'_, AppState>, no: u64) -> Result<Vec<HexDumpLine>, String> {
    let engine = state.capture_engine.lock();
    let raw_data = engine.get_raw_data(no)
        .ok_or_else(|| format!("Packet {} raw data not found", no))?;
    Ok(format_hex_dump(&raw_data))
}

#[tauri::command]
pub fn apply_display_filter(
    state: State<'_, AppState>,
    filter_expr: String,
) -> Result<Vec<PacketMetadata>, String> {
    let engine = state.capture_engine.lock();
    let all = engine.get_all_metadata();
    display::filter_packets(&all, &filter_expr)
}

#[tauri::command]
pub fn get_sessions(state: State<'_, AppState>) -> Result<Vec<SessionInfo>, String> {
    let tracker = state.session_tracker.lock();
    Ok(tracker.get_sessions())
}

#[tauri::command]
pub fn trace_tcp_stream(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<TcpStreamData, String> {
    let mut tracker = state.session_tracker.lock();
    tracker.get_tcp_stream(&session_id)
        .ok_or_else(|| format!("TCP stream '{}' not found", session_id))
}

#[tauri::command]
pub fn get_stats(state: State<'_, AppState>) -> Result<StatsSnapshot, String> {
    let collector = state.stats_collector.lock();
    Ok(collector.get_snapshot())
}

#[tauri::command]
pub fn export_pcap(
    state: State<'_, AppState>,
    path: String,
    filtered_only: bool,
    filter_expr: Option<String>,
) -> Result<(), String> {
    let engine = state.capture_engine.lock();

    let metadata_list = if filtered_only {
        if let Some(expr) = filter_expr {
            let all_meta = engine.get_all_metadata();
            display::filter_packets(&all_meta, &expr)?
        } else {
            engine.get_all_metadata()
        }
    } else {
        engine.get_all_metadata()
    };

    let raw_packets: Vec<RawPacket> = metadata_list.iter()
        .filter_map(|m| {
            engine.get_raw_data(m.no).map(|data| RawPacket {
                timestamp_secs: m.timestamp_secs,
                timestamp_micros: m.timestamp_micros,
                data,
            })
        })
        .collect();

    pcap_export::write_pcap_file(&path, &raw_packets)
}

#[tauri::command]
pub fn import_pcap(
    state: State<'_, AppState>,
    path: String,
) -> Result<Vec<PacketMetadata>, String> {
    let raw_packets = pcap_import::read_pcap_file(&path)?;
    let mut engine = state.capture_engine.lock();
    let session_tracker = state.session_tracker.clone();
    let stats_collector = state.stats_collector.clone();

    let mut result = Vec::new();
    for raw in &raw_packets {
        let no = engine.next_packet_no();
        let meta = protocol::parse_packet_metadata(no, raw);

        {
            let mut tracker = session_tracker.lock();
            tracker.process_packet(&meta, raw);
        }
        {
            let mut stats = stats_collector.lock();
            stats.record_packet(&meta);
        }

        engine.store_imported_packet(meta.clone(), raw.clone());
        result.push(meta);
    }

    Ok(result)
}

#[tauri::command]
pub fn load_sslkeylog(path: String) -> Result<usize, String> {
    let mut decryptor = TlsDecryptor::new();
    decryptor.load_sslkeylog(&path)?;
    Ok(decryptor.key_count())
}

fn format_hex_dump(data: &[u8]) -> Vec<HexDumpLine> {
    let mut lines = Vec::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = format!("{:04x}", i * 16);
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        let ascii: String = chunk.iter()
            .map(|&b| if b >= 0x20 && b <= 0x7e { b as char } else { '.' })
            .collect();
        lines.push(HexDumpLine { offset, hex, ascii });
    }
    lines
}

#[tauri::command]
pub fn set_packet_mark(
    state: State<'_, AppState>,
    packet_no: u64,
    level: String,
    comment: String,
) -> Result<(), String> {
    let mark_level = MarkLevel::from_str(&level)
        .ok_or_else(|| format!("Invalid mark level: {}", level))?;
    let mut engine = state.capture_engine.lock();
    engine.set_mark(packet_no, mark_level, comment)
}

#[tauri::command]
pub fn remove_packet_mark(
    state: State<'_, AppState>,
    packet_no: u64,
) -> Result<(), String> {
    let mut engine = state.capture_engine.lock();
    engine.remove_mark(packet_no)
}

#[tauri::command]
pub fn get_packet_mark(
    state: State<'_, AppState>,
    packet_no: u64,
) -> Result<Option<PacketMark>, String> {
    let engine = state.capture_engine.lock();
    Ok(engine.get_mark(packet_no))
}

#[tauri::command]
pub fn get_all_marks(state: State<'_, AppState>) -> Result<Vec<PacketMark>, String> {
    let engine = state.capture_engine.lock();
    Ok(engine.get_all_marks())
}

#[tauri::command]
pub fn get_tcp_timeline(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<TcpTimelineData, String> {
    let session_tracker = state.session_tracker.lock();
    let packet_nos = session_tracker
        .get_session_packet_nos(&session_id)
        .ok_or_else(|| format!("Session '{}' not found", session_id))?;

    let (client_addr, client_port, server_addr, server_port) = session_tracker
        .get_session_client_info(&session_id)
        .ok_or_else(|| format!("Session client info not found"))?;

    drop(session_tracker);

    let engine = state.capture_engine.lock();
    let total_packets = packet_nos.len() as u64;
    let is_truncated = packet_nos.len() > 5000;

    let selected_nos: Vec<u64> = if is_truncated {
        let first_100: Vec<u64> = packet_nos.iter().take(100).cloned().collect();
        let last_100: Vec<u64> = packet_nos.iter().rev().take(100).cloned().collect();
        let mut result = first_100;
        result.extend(last_100.into_iter().rev());
        result
    } else {
        packet_nos.clone()
    };

    let mut entries = Vec::new();
    for no in selected_nos {
        if let Some(raw_data) = engine.get_raw_data(no) {
            if let Ok(packet) = SlicedPacket::from_ethernet(&raw_data) {
                if let Some(etherparse::TransportSlice::Tcp(tcp)) = &packet.transport {
                    let meta = engine.get_metadata(no);
                    let is_from_client = if let Some(m) = &meta {
                        m.src_addr == client_addr && m.src_port == Some(client_port)
                    } else {
                        false
                    };

                    let flags = TcpFlags::from_bits(
                        (tcp.fin() as u8) | (tcp.syn() as u8 * 2) | (tcp.rst() as u8 * 4)
                            | (tcp.psh() as u8 * 8) | (tcp.ack() as u8 * 16) | (tcp.urg() as u8 * 32),
                    );

                    let payload_size = if let Some(ip) = &packet.ip {
                        match ip {
                            etherparse::InternetSlice::Ipv4(ipv4, _) => {
                                ipv4.total_len() as u32 - ipv4.ihl() as u32 * 4 - tcp.data_offset() as u32 * 4
                            }
                            _ => 0,
                        }
                    } else {
                        0
                    };

                    let entry = TcpSequenceEntry {
                        packet_no: no,
                        timestamp_secs: meta.as_ref().map(|m| m.timestamp_secs).unwrap_or(0),
                        timestamp_micros: meta.as_ref().map(|m| m.timestamp_micros).unwrap_or(0),
                        direction: is_from_client,
                        seq_num: tcp.sequence_number(),
                        ack_num: tcp.acknowledgment_number(),
                        payload_size: payload_size.max(0) as u32,
                        flags: flags.to_string_flags(),
                        is_retransmission: false,
                        window_size: tcp.window_size(),
                    };
                    entries.push(entry);
                }
            }
        }
    }

    Ok(TcpTimelineData {
        session_id,
        client_addr,
        client_port,
        server_addr,
        server_port,
        entries,
        is_truncated,
        total_packets,
    })
}

const MAX_TEMPLATES: usize = 50;

fn get_templates_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let app_dir = app
        .path_resolver()
        .app_data_dir()
        .ok_or_else(|| "Failed to get app data directory".to_string())?;
    fs::create_dir_all(&app_dir).map_err(|e| e.to_string())?;
    Ok(app_dir.join("capture_templates.json"))
}

#[tauri::command]
pub fn save_capture_template(
    app: tauri::AppHandle,
    name: String,
    interface_name: String,
    bpf_filter: String,
    promiscuous: bool,
    description: Option<String>,
) -> Result<(), String> {
    let path = get_templates_path(&app)?;
    let mut templates: Vec<CaptureTemplate> = if path.exists() {
        let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        Vec::new()
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if let Some(existing) = templates.iter_mut().find(|t| t.name == name) {
        existing.interface_name = interface_name;
        existing.bpf_filter = bpf_filter;
        existing.promiscuous = promiscuous;
        existing.description = description;
        existing.updated_at = now;
    } else {
        if templates.len() >= MAX_TEMPLATES {
            return Err("模板数量已达上限，请删除旧模板".into());
        }
        templates.push(CaptureTemplate {
            name,
            interface_name,
            bpf_filter,
            promiscuous,
            description,
            created_at: now,
            updated_at: now,
        });
    }

    let content = serde_json::to_string_pretty(&templates).map_err(|e| e.to_string())?;
    fs::write(&path, content).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn load_capture_templates(app: tauri::AppHandle) -> Result<Vec<CaptureTemplate>, String> {
    let path = get_templates_path(&app)?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let templates: Vec<CaptureTemplate> = serde_json::from_str(&content).unwrap_or_default();
    Ok(templates)
}

#[tauri::command]
pub fn delete_capture_template(app: tauri::AppHandle, name: String) -> Result<(), String> {
    let path = get_templates_path(&app)?;
    if !path.exists() {
        return Ok(());
    }
    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let mut templates: Vec<CaptureTemplate> = serde_json::from_str(&content).unwrap_or_default();
    templates.retain(|t| t.name != name);
    let content = serde_json::to_string_pretty(&templates).map_err(|e| e.to_string())?;
    fs::write(&path, content).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn export_templates(app: tauri::AppHandle, path: String) -> Result<(), String> {
    let templates = load_capture_templates(app)?;
    let content = serde_json::to_string_pretty(&templates).map_err(|e| e.to_string())?;
    fs::write(&path, content).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn import_templates(app: tauri::AppHandle, path: String) -> Result<usize, String> {
    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let import_templates: Vec<CaptureTemplate> =
        serde_json::from_str(&content).map_err(|e| e.to_string())?;

    let templates_path = get_templates_path(&app)?;
    let mut existing: Vec<CaptureTemplate> = if templates_path.exists() {
        let content = fs::read_to_string(&templates_path).map_err(|e| e.to_string())?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        Vec::new()
    };

    let mut imported = 0;
    for t in import_templates {
        if existing.iter().any(|e| e.name == t.name) {
            continue;
        }
        if existing.len() >= MAX_TEMPLATES {
            break;
        }
        existing.push(t);
        imported += 1;
    }

    let content = serde_json::to_string_pretty(&existing).map_err(|e| e.to_string())?;
    fs::write(&templates_path, content).map_err(|e| e.to_string())?;
    Ok(imported)
}
