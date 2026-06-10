use std::io::Write;
use byteorder::{WriteBytesExt, LittleEndian};
use crate::models::RawPacket;

const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_LINK_TYPE_ETHERNET: u32 = 1;

pub struct PcapWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut writer: W) -> Result<Self, String> {
        writer.write_u32::<LittleEndian>(PCAP_MAGIC).map_err(|e| e.to_string())?;
        writer.write_u16::<LittleEndian>(PCAP_VERSION_MAJOR).map_err(|e| e.to_string())?;
        writer.write_u16::<LittleEndian>(PCAP_VERSION_MINOR).map_err(|e| e.to_string())?;
        writer.write_i32::<LittleEndian>(0).map_err(|e| e.to_string())?;
        writer.write_u32::<LittleEndian>(0).map_err(|e| e.to_string())?;
        writer.write_u32::<LittleEndian>(PCAP_LINK_TYPE_ETHERNET).map_err(|e| e.to_string())?;
        writer.write_u32::<LittleEndian>(65535).map_err(|e| e.to_string())?;

        Ok(Self { writer })
    }

    pub fn write_packet(&mut self, packet: &RawPacket) -> Result<(), String> {
        self.writer.write_u32::<LittleEndian>(packet.timestamp_secs as u32).map_err(|e| e.to_string())?;
        self.writer.write_u32::<LittleEndian>(packet.timestamp_micros).map_err(|e| e.to_string())?;
        self.writer.write_u32::<LittleEndian>(packet.data.len() as u32).map_err(|e| e.to_string())?;
        self.writer.write_u32::<LittleEndian>(packet.data.len() as u32).map_err(|e| e.to_string())?;
        self.writer.write_all(&packet.data).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn write_packets(&mut self, packets: &[RawPacket]) -> Result<(), String> {
        for packet in packets {
            self.write_packet(packet)?;
        }
        Ok(())
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

pub fn write_pcap_file(path: &str, packets: &[RawPacket]) -> Result<(), String> {
    let file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    let mut writer = PcapWriter::new(file)?;
    writer.write_packets(packets)?;
    Ok(())
}
