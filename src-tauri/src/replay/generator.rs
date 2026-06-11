use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::models::{PacketMetadata, ProtocolType};
use super::models::AttackPattern;

pub struct GeneratedTraffic {
    pub packets: Vec<PacketMetadata>,
    pub raw_data: Vec<Vec<u8>>,
}

pub fn generate_traffic(pattern: &AttackPattern, target_ip_override: Option<String>) -> GeneratedTraffic {
    let mut rng = rand::thread_rng();
    let params = &pattern.params;

    let target_ip = target_ip_override
        .or_else(|| params.target_ip.clone())
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let base_src_ip = if !params.random_source_ip {
        format!(
            "{}.{}.{}.{}",
            rng.gen_range(1..224),
            rng.gen_range(0..256),
            rng.gen_range(0..256),
            rng.gen_range(1..255)
        )
    } else {
        String::new()
    };

    let protocol = match params.protocol.to_uppercase().as_str() {
        "TCP" => ProtocolType::TCP,
        "UDP" => ProtocolType::UDP,
        "ICMP" => ProtocolType::ICMP,
        "HTTP" => ProtocolType::HTTP,
        "DNS" => ProtocolType::DNS,
        "ARP" => ProtocolType::ARP,
        "TLS" => ProtocolType::TLS,
        _ => ProtocolType::TCP,
    };

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let now_micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.subsec_nanos() / 1000) as u32)
        .unwrap_or(0);

    let interval_micros = if params.packets_per_second > 0 {
        1_000_000u64 / params.packets_per_second as u64
    } else {
        1_000_000u64
    };

    let mut packets = Vec::with_capacity(params.packet_count as usize);
    let mut raw_data = Vec::with_capacity(params.packet_count as usize);

    for i in 0..params.packet_count {
        let offset_micros = i as u64 * interval_micros;
        let ts_secs = now_secs + offset_micros / 1_000_000;
        let ts_micros = (now_micros as u64 + offset_micros % 1_000_000) as u32;

        let src_ip = if params.random_source_ip {
            format!(
                "{}.{}.{}.{}",
                rng.gen_range(1..224),
                rng.gen_range(0..256),
                rng.gen_range(0..256),
                rng.gen_range(1..255)
            )
        } else {
            base_src_ip.clone()
        };

        let src_port = if params.source_port_max > params.source_port_min {
            rng.gen_range(params.source_port_min..=params.source_port_max)
        } else {
            params.source_port_min
        };

        let dst_port = if params.target_port_max > params.target_port_min {
            match pattern.category {
                super::models::AttackCategory::PortScan => {
                    let port_range = params.target_port_max - params.target_port_min + 1;
                    params.target_port_min + (i as u16 % port_range.max(1))
                }
                _ => rng.gen_range(params.target_port_min..=params.target_port_max),
            }
        } else {
            params.target_port_min
        };

        let tcp_flags_str = match &params.tcp_flags {
            Some(flags) if protocol == ProtocolType::TCP || protocol == ProtocolType::HTTP => {
                Some(flags.join(", "))
            }
            None if protocol == ProtocolType::TCP || protocol == ProtocolType::HTTP => {
                Some("SYN".to_string())
            }
            _ => None,
        };

        let length = generate_packet_length(protocol, &pattern.params, &mut rng);

        let summary = generate_summary(
            protocol,
            &src_ip,
            src_port,
            &target_ip,
            dst_port,
            tcp_flags_str.as_deref(),
            &pattern.params,
        );

        let meta = PacketMetadata {
            no: (i + 1) as u64,
            timestamp_secs: ts_secs,
            timestamp_micros: ts_micros,
            src_addr: src_ip.clone(),
            src_port: Some(src_port),
            dst_addr: target_ip.clone(),
            dst_port: Some(dst_port),
            protocol,
            length,
            summary,
            ttl: Some(rng.gen_range(32..128)),
            window_size: if matches!(protocol, ProtocolType::TCP | ProtocolType::HTTP) {
                Some(rng.gen_range(1024..65535))
            } else {
                None
            },
            tcp_flags: tcp_flags_str,
            ip_id: Some(rng.gen_range(0..65535)),
            fragment_offset: Some(0),
            blocked: false,
        };

        let raw = generate_raw_packet(protocol, &src_ip, src_port, &target_ip, dst_port, length as usize, &pattern.params);

        packets.push(meta);
        raw_data.push(raw);
    }

    GeneratedTraffic { packets, raw_data }
}

fn generate_packet_length(
    protocol: ProtocolType,
    params: &super::models::AttackPatternParams,
    rng: &mut impl Rng,
) -> u32 {
    match protocol {
        ProtocolType::TCP | ProtocolType::HTTP | ProtocolType::TLS => {
            if params.http_method.is_some() {
                rng.gen_range(200..800)
            } else {
                rng.gen_range(40..1500)
            }
        }
        ProtocolType::UDP | ProtocolType::DNS => {
            if params.dns_domain.is_some() {
                rng.gen_range(60..512)
            } else {
                rng.gen_range(28..1500)
            }
        }
        ProtocolType::ICMP => rng.gen_range(64..1024),
        ProtocolType::ARP => 42,
        _ => rng.gen_range(64..1500),
    }
}

fn generate_summary(
    protocol: ProtocolType,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    tcp_flags: Option<&str>,
    params: &super::models::AttackPatternParams,
) -> String {
    match protocol {
        ProtocolType::TCP | ProtocolType::HTTP | ProtocolType::TLS => {
            let flags = tcp_flags.unwrap_or("SYN");
            if let Some(method) = &params.http_method {
                let path = params.http_path.as_deref().unwrap_or("/");
                format!("{} {} {}:{} -> {}:{} {} {}", protocol.as_str(), method, src_ip, src_port, dst_ip, dst_port, path, flags)
            } else {
                format!("{} {}:{} -> {}:{} {}", protocol.as_str(), src_ip, src_port, dst_ip, dst_port, flags)
            }
        }
        ProtocolType::UDP | ProtocolType::DNS => {
            if let Some(domain) = &params.dns_domain {
                format!("DNS Query {}:{} -> {}:53 {} {}", src_ip, src_port, dst_ip, domain, protocol.as_str())
            } else {
                format!("{} {}:{} -> {}:{}", protocol.as_str(), src_ip, src_port, dst_ip, dst_port)
            }
        }
        ProtocolType::ICMP => format!("ICMP Echo Request {} -> {}", src_ip, dst_ip),
        ProtocolType::ARP => format!("ARP Request who-has {} tell {}", dst_ip, src_ip),
        _ => format!("{} {}:{} -> {}:{}", protocol.as_str(), src_ip, src_port, dst_ip, dst_port),
    }
}

fn generate_raw_packet(
    protocol: ProtocolType,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    length: usize,
    params: &super::models::AttackPatternParams,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(length.max(64));

    let src_ip_bytes = ip_to_bytes(src_ip);
    let dst_ip_bytes = ip_to_bytes(dst_ip);

    for _ in 0..6 {
        data.push(rand::random::<u8>());
    }
    for _ in 0..6 {
        data.push(rand::random::<u8>());
    }
    data.extend_from_slice(&[0x08, 0x00]);

    data.push(0x45);
    data.push(0x00);
    let total_len = (length as u16).to_be_bytes();
    data.extend_from_slice(&total_len);
    data.extend_from_slice(&rand::random::<u16>().to_be_bytes());
    data.extend_from_slice(&0x4000u16.to_be_bytes());
    data.push(rand::random::<u8>());

    match protocol {
        ProtocolType::TCP | ProtocolType::HTTP | ProtocolType::TLS => {
            data.push(0x06);
        }
        ProtocolType::UDP | ProtocolType::DNS => {
            data.push(0x11);
        }
        ProtocolType::ICMP => {
            data.push(0x01);
        }
        _ => {
            data.push(0x06);
        }
    }
    data.extend_from_slice(&0u16.to_be_bytes());
    data.extend_from_slice(&src_ip_bytes);
    data.extend_from_slice(&dst_ip_bytes);

    match protocol {
        ProtocolType::TCP | ProtocolType::HTTP | ProtocolType::TLS => {
            data.extend_from_slice(&src_port.to_be_bytes());
            data.extend_from_slice(&dst_port.to_be_bytes());
            data.extend_from_slice(&rand::random::<u32>().to_be_bytes());
            data.extend_from_slice(&rand::random::<u32>().to_be_bytes());
            data.push(0x50);

            let mut flags_byte: u8 = 0;
            if let Some(flag_list) = &params.tcp_flags {
                for f in flag_list {
                    match f.to_uppercase().as_str() {
                        "SYN" => flags_byte |= 0x02,
                        "ACK" => flags_byte |= 0x10,
                        "FIN" => flags_byte |= 0x01,
                        "RST" => flags_byte |= 0x04,
                        "PSH" => flags_byte |= 0x08,
                        "URG" => flags_byte |= 0x20,
                        _ => {}
                    }
                }
            } else {
                flags_byte = 0x02;
            }
            data.push(flags_byte);

            data.extend_from_slice(&rand::random::<u16>().to_be_bytes());
            data.extend_from_slice(&0u16.to_be_bytes());
            data.extend_from_slice(&0u16.to_be_bytes());
        }
        ProtocolType::UDP | ProtocolType::DNS => {
            data.extend_from_slice(&src_port.to_be_bytes());
            data.extend_from_slice(&dst_port.to_be_bytes());
            let udp_len = ((length - 34) as u16).to_be_bytes();
            data.extend_from_slice(&udp_len);
            data.extend_from_slice(&0u16.to_be_bytes());

            if params.dns_domain.is_some() {
                data.extend_from_slice(&rand::random::<u16>().to_be_bytes());
                data.extend_from_slice(&0x0100u16.to_be_bytes());
                data.extend_from_slice(&0x0001u16.to_be_bytes());
                data.extend_from_slice(&0x0000u16.to_be_bytes());
                data.extend_from_slice(&0x0000u16.to_be_bytes());
                data.extend_from_slice(&0x0000u16.to_be_bytes());
            }
        }
        ProtocolType::ICMP => {
            data.push(0x08);
            data.push(0x00);
            data.extend_from_slice(&0u16.to_be_bytes());
            data.extend_from_slice(&rand::random::<u16>().to_be_bytes());
            data.extend_from_slice(&rand::random::<u16>().to_be_bytes());
        }
        _ => {}
    }

    if let Some(payload) = &params.payload_pattern {
        data.extend_from_slice(payload.as_bytes());
    }

    while data.len() < length {
        data.push(rand::random::<u8>());
    }
    if data.len() > length {
        data.truncate(length);
    }

    data
}

fn ip_to_bytes(ip: &str) -> [u8; 4] {
    let parts: Vec<u8> = ip
        .split('.')
        .filter_map(|s| s.parse::<u8>().ok())
        .collect();
    if parts.len() == 4 {
        [parts[0], parts[1], parts[2], parts[3]]
    } else {
        [127, 0, 0, 1]
    }
}
