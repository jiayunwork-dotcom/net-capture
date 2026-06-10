use std::io::Read;
use byteorder::{ReadBytesExt, LittleEndian};
use crate::models::RawPacket;

pub struct PcapReader<R: Read> {
    reader: R,
    swap_endian: bool,
    link_type: u32,
    snap_len: u32,
}

impl<R: Read> PcapReader<R> {
    pub fn new(mut reader: R) -> Result<Self, String> {
        let magic = reader.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;

        let swap_endian = if magic == 0xa1b2c3d4 {
            false
        } else if magic == 0xd4c3b2a1 {
            true
        } else {
            return Err(format!("Invalid PCAP magic number: 0x{:08x}", magic));
        };

        let (version_major, version_minor): (u16, u16) = if swap_endian {
            let mj = reader.read_u16::<LittleEndian>().map_err(|e| e.to_string())?;
            let mn = reader.read_u16::<LittleEndian>().map_err(|e| e.to_string())?;
            (mj.to_be(), mn.to_be())
        } else {
            let mj = reader.read_u16::<LittleEndian>().map_err(|e| e.to_string())?;
            let mn = reader.read_u16::<LittleEndian>().map_err(|e| e.to_string())?;
            (mj, mn)
        };

        let _this_zone = reader.read_i32::<LittleEndian>().map_err(|e| e.to_string())?;
        let _sig_figs = reader.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let snap_len = reader.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let link_type = reader.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;

        let _ = (version_major, version_minor);

        Ok(Self {
            reader,
            swap_endian,
            link_type,
            snap_len,
        })
    }

    pub fn link_type(&self) -> u32 {
        self.link_type
    }

    pub fn read_packet(&mut self) -> Result<Option<RawPacket>, String> {
        let ts_sec = match self.reader.read_u32::<LittleEndian>() {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        let ts_usec = self.reader.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let incl_len = self.reader.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let _orig_len = self.reader.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;

        let incl_len = if self.swap_endian {
            incl_len.swap_bytes()
        } else {
            incl_len
        };

        let mut data = vec![0u8; incl_len as usize];
        self.reader.read_exact(&mut data).map_err(|e| e.to_string())?;

        Ok(Some(RawPacket {
            timestamp_secs: ts_sec as u64,
            timestamp_micros: ts_usec,
            data,
        }))
    }

    pub fn read_all_packets(&mut self) -> Result<Vec<RawPacket>, String> {
        let mut packets = Vec::new();
        while let Some(pkt) = self.read_packet()? {
            packets.push(pkt);
        }
        Ok(packets)
    }
}

pub fn read_pcap_file(path: &str) -> Result<Vec<RawPacket>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut reader = PcapReader::new(file)?;
    reader.read_all_packets()
}
