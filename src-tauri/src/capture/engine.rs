use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::collections::{VecDeque, HashMap};
use crossbeam_channel::{Sender, Receiver, bounded};
use pcap::{Capture, Device, PacketCodec};
use crate::models::{PacketMetadata, RawPacket, CaptureStatus};
use crate::protocol;
use crate::session::SessionTracker;
use crate::stats::StatsCollector;

const MAX_METADATA_COUNT: usize = 500_000;

pub struct CaptureEngine {
    is_capturing: Arc<AtomicBool>,
    packet_counter: Arc<AtomicU64>,
    dropped_count: Arc<AtomicU64>,
    interface_name: Option<String>,
    metadata_buffer: VecDeque<PacketMetadata>,
    raw_data_store: HashMap<u64, Vec<u8>>,
    capture_handle: Option<std::thread::JoinHandle<()>>,
    stop_flag: Arc<AtomicBool>,
    tx: Option<Sender<CaptureEvent>>,
    rx: Option<Receiver<CaptureEvent>>,
}

pub enum CaptureEvent {
    NewPacket(PacketMetadata, Vec<u8>),
    Error(String),
}

struct RawCodec;

impl PacketCodec for RawCodec {
    type Item = RawPacket;
    fn decode(&mut self, packet: pcap::Packet) -> Self::Item {
        let ts = packet.header.ts;
        RawPacket {
            timestamp_secs: ts.tv_sec as u64,
            timestamp_micros: ts.tv_usec as u32,
            data: packet.data.to_vec(),
        }
    }
}

impl CaptureEngine {
    pub fn new() -> Self {
        let (tx, rx) = bounded(65536);
        Self {
            is_capturing: Arc::new(AtomicBool::new(false)),
            packet_counter: Arc::new(AtomicU64::new(0)),
            dropped_count: Arc::new(AtomicU64::new(0)),
            interface_name: None,
            metadata_buffer: VecDeque::with_capacity(MAX_METADATA_COUNT),
            raw_data_store: HashMap::new(),
            capture_handle: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
            tx: Some(tx),
            rx: Some(rx),
        }
    }

    pub fn start_capture(
        &mut self,
        interface_name: &str,
        promiscuous: bool,
        bpf_filter: Option<&str>,
        session_tracker: Arc<parking_lot::Mutex<SessionTracker>>,
        stats_collector: Arc<parking_lot::Mutex<StatsCollector>>,
    ) -> Result<(), String> {
        if self.is_capturing.load(Ordering::SeqCst) {
            return Err("Already capturing".into());
        }

        let device = Device::list()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|d| d.name == interface_name)
            .ok_or_else(|| format!("Interface '{}' not found", interface_name))?;

        let mut cap = Capture::from_device(device)
            .map_err(|e| e.to_string())?
            .promisc(promiscuous)
            .snaplen(65535)
            .timeout(1000)
            .open()
            .map_err(|e| e.to_string())?;

        if let Some(filter) = bpf_filter {
            cap.filter(filter, true)
                .map_err(|e| format!("BPF filter error: {}", e))?;
        }

        self.interface_name = Some(interface_name.to_string());
        self.packet_counter.store(0, Ordering::SeqCst);
        self.dropped_count.store(0, Ordering::SeqCst);
        self.metadata_buffer.clear();
        self.raw_data_store.clear();
        self.stop_flag.store(false, Ordering::SeqCst);
        self.is_capturing.store(true, Ordering::SeqCst);

        let stop_flag = self.stop_flag.clone();
        let packet_counter = self.packet_counter.clone();
        let is_capturing = self.is_capturing.clone();
        let tx = self.tx.clone().unwrap();

        let handle = std::thread::Builder::new()
            .name("capture-thread".into())
            .spawn(move || {
                let codec = RawCodec;
                let mut cap = cap;
                let iter = cap.iter(codec);

                for raw_pkt in iter {
                    if stop_flag.load(Ordering::SeqCst) {
                        break;
                    }

                    let raw_pkt = match raw_pkt {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    let raw_data = raw_pkt.data.clone();
                    let no = packet_counter.fetch_add(1, Ordering::SeqCst);
                    let meta = protocol::parse_packet_metadata(no, &raw_pkt);

                    {
                        let mut tracker = session_tracker.lock();
                        tracker.process_packet(&meta, &raw_pkt);
                    }

                    {
                        let mut stats = stats_collector.lock();
                        stats.record_packet(&meta);
                    }

                    if tx.send(CaptureEvent::NewPacket(meta, raw_data)).is_err() {
                        break;
                    }
                }

                is_capturing.store(false, Ordering::SeqCst);
            })
            .map_err(|e| e.to_string())?;

        self.capture_handle = Some(handle);
        Ok(())
    }

    pub fn stop_capture(&mut self) -> Result<(), String> {
        if !self.is_capturing.load(Ordering::SeqCst) {
            return Err("Not capturing".into());
        }
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.capture_handle.take() {
            let _ = handle.join();
        }
        self.is_capturing.store(false, Ordering::SeqCst);
        Ok(())
    }

    pub fn get_status(&self) -> CaptureStatus {
        CaptureStatus {
            is_capturing: self.is_capturing.load(Ordering::SeqCst),
            interface_name: self.interface_name.clone(),
            packet_count: self.packet_counter.load(Ordering::SeqCst),
            dropped_count: self.dropped_count.load(Ordering::SeqCst) as u32,
        }
    }

    pub fn next_packet_no(&self) -> u64 {
        self.packet_counter.fetch_add(1, Ordering::SeqCst)
    }

    pub fn drain_new_packets(&mut self) -> Vec<PacketMetadata> {
        if let Some(rx) = &self.rx {
            let mut new_packets = Vec::new();
            while let Ok(event) = rx.try_recv() {
                match event {
                    CaptureEvent::NewPacket(meta, raw_data) => {
                        let no = meta.no;
                        if self.metadata_buffer.len() >= MAX_METADATA_COUNT {
                            if let Some(evicted) = self.metadata_buffer.pop_front() {
                                self.raw_data_store.remove(&evicted.no);
                            }
                        }
                        self.raw_data_store.insert(no, raw_data);
                        self.metadata_buffer.push_back(meta.clone());
                        new_packets.push(meta);
                    }
                    CaptureEvent::Error(_) => {}
                }
            }
            new_packets
        } else {
            Vec::new()
        }
    }

    pub fn get_metadata(&self, no: u64) -> Option<PacketMetadata> {
        self.metadata_buffer.iter().find(|m| m.no == no).cloned()
    }

    pub fn get_all_metadata(&self) -> Vec<PacketMetadata> {
        self.metadata_buffer.iter().cloned().collect()
    }

    pub fn get_raw_data(&self, no: u64) -> Option<Vec<u8>> {
        self.raw_data_store.get(&no).cloned()
    }

    pub fn store_raw_packet(&mut self, no: u64, raw: RawPacket) {
        if self.metadata_buffer.len() >= MAX_METADATA_COUNT {
            if let Some(evicted) = self.metadata_buffer.pop_front() {
                self.raw_data_store.remove(&evicted.no);
            }
        }
        self.raw_data_store.insert(no, raw.data);
    }

    pub fn store_imported_packet(&mut self, meta: PacketMetadata, raw: RawPacket) {
        if self.metadata_buffer.len() >= MAX_METADATA_COUNT {
            if let Some(evicted) = self.metadata_buffer.pop_front() {
                self.raw_data_store.remove(&evicted.no);
            }
        }
        self.raw_data_store.insert(meta.no, raw.data);
        self.metadata_buffer.push_back(meta);
    }

    pub fn validate_bpf(&self, filter: &str) -> Result<(), String> {
        let device = Device::list()
            .map_err(|e| e.to_string())?
            .into_iter()
            .next()
            .ok_or("No device available")?;

        let mut cap = Capture::from_device(device)
            .map_err(|e| e.to_string())?
            .promisc(false)
            .snaplen(65535)
            .open()
            .map_err(|e| e.to_string())?;

        cap.filter(filter, true)
            .map_err(|e| format!("表达式无效: {}", e))?;

        Ok(())
    }
}
