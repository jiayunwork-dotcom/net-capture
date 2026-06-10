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
pub fn get_packet_detail(
    state: State<'_, AppState>,
    no: u64,
    raw_data: Option<Vec<u8>>,
) -> Result<PacketDetail, String> {
    let raw = if let Some(data) = raw_data {
        RawPacket {
            timestamp_secs: 0,
            timestamp_micros: 0,
            data,
        }
    } else {
        let engine = state.capture_engine.lock();
        engine.get_raw_packet(no)
            .map(|r| r.clone())
            .ok_or_else(|| format!("Packet {} not found", no))?
    };

    let mut detail = protocol::parse_packet_detail(&raw);
    detail.no = no;
    Ok(detail)
}

#[tauri::command]
pub fn get_hex_dump(raw_data: Vec<u8>) -> Result<Vec<HexDumpLine>, String> {
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

    let packets: Vec<RawPacket> = if filtered_only {
        if let Some(expr) = filter_expr {
            let all_meta = engine.get_all_metadata();
            let filtered = display::filter_packets(&all_meta, &expr)?;
            filtered.iter()
                .filter_map(|m| engine.get_raw_packet(m.no).cloned())
                .collect()
        } else {
            engine.get_all_metadata().iter()
                .filter_map(|m| engine.get_raw_packet(m.no).cloned())
                .collect()
        }
    } else {
        engine.get_all_metadata().iter()
            .filter_map(|m| engine.get_raw_packet(m.no).cloned())
            .collect()
    };

    pcap_export::write_pcap_file(&path, &packets)
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
        let no = engine.get_status().packet_count;
        let meta = protocol::parse_packet_metadata(no, raw);

        {
            let mut tracker = session_tracker.lock();
            tracker.process_packet(&meta, raw);
        }
        {
            let mut stats = stats_collector.lock();
            stats.record_packet(&meta);
        }

        engine.store_raw_packet(raw.clone());
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
