use crate::models::*;
use etherparse::SlicedPacket;

pub fn parse_packet_metadata(no: u64, raw: &RawPacket) -> PacketMetadata {
    match SlicedPacket::from_ethernet(&raw.data) {
        Ok(packet) => {
            let (src_addr, src_port, dst_addr, dst_port, protocol, summary, ttl, window_size, tcp_flags, ip_id, fragment_offset) =
                extract_packet_info(&packet);

            PacketMetadata {
                no,
                timestamp_secs: raw.timestamp_secs,
                timestamp_micros: raw.timestamp_micros,
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                protocol,
                length: raw.data.len() as u32,
                summary,
                ttl,
                window_size,
                tcp_flags,
                ip_id,
                fragment_offset,
                blocked: false,
            }
        }
        Err(_) => PacketMetadata {
            no,
            timestamp_secs: raw.timestamp_secs,
            timestamp_micros: raw.timestamp_micros,
            src_addr: String::new(),
            src_port: None,
            dst_addr: String::new(),
            dst_port: None,
            protocol: ProtocolType::Unknown,
            length: raw.data.len() as u32,
            summary: "Parse error".into(),
            ttl: None,
            window_size: None,
            tcp_flags: None,
            ip_id: None,
            fragment_offset: None,
            blocked: false,
        },
    }
}

pub fn parse_packet_detail(raw: &RawPacket) -> PacketDetail {
    let mut layers = Vec::new();

    match SlicedPacket::from_ethernet(&raw.data) {
        Ok(packet) => {
            if let Some(link) = &packet.link {
                let eth_layer = parse_ethernet_layer(link);
                layers.push(eth_layer);
            }

            if let Some(vlan) = &packet.vlan {
                layers.push(parse_vlan_layer(vlan));
            }

            if let Some(ip) = &packet.ip {
                let net_layer = parse_ip_layer(ip);
                layers.push(net_layer);
            }

            if let Some(transport) = &packet.transport {
                let transport_layer = parse_transport_layer(transport);
                layers.push(transport_layer);
            }

            let app_data = packet.payload;
            if !app_data.is_empty() {
                if let Some(app_layer) = parse_application_layer(app_data, &packet) {
                    layers.push(app_layer);
                }
            }
        }
        Err(_) => {
            layers.push(ProtocolLayer {
                protocol: "Error".into(),
                fields: vec![FieldEntry {
                    name: "Error".into(),
                    value: "Failed to parse packet".into(),
                    byte_range: (0, raw.data.len()),
                }],
                byte_range: (0, raw.data.len()),
            });
        }
    }

    PacketDetail {
        no: 0,
        layers,
        raw_data: raw.data.clone(),
    }
}

fn extract_packet_info(packet: &SlicedPacket) -> (String, Option<u16>, String, Option<u16>, ProtocolType, String, Option<u8>, Option<u16>, Option<String>, Option<u16>, Option<u16>) {
    let mut src_addr = String::new();
    let mut dst_addr = String::new();
    let mut src_port = None;
    let mut dst_port = None;
    let mut protocol = ProtocolType::Unknown;
    let mut summary = String::new();
    let mut ttl = None;
    let mut window_size = None;
    let mut tcp_flags = None;
    let mut ip_id = None;
    let mut fragment_offset = None;

    if let Some(link) = &packet.link {
        match link {
            etherparse::LinkSlice::Ethernet2(eth) => {
                src_addr = format_mac_arr(eth.source());
                dst_addr = format_mac_arr(eth.destination());
                protocol = ProtocolType::Ethernet;
                summary = format!("EtherType: 0x{:04x}", eth.ether_type());
            }
        }
    }

    if let Some(ip) = &packet.ip {
        match ip {
            etherparse::InternetSlice::Ipv4(ipv4, _exts) => {
                src_addr = format!("{}", ipv4.source_addr());
                dst_addr = format!("{}", ipv4.destination_addr());
                ttl = Some(ipv4.ttl());
                ip_id = Some(ipv4.identification());
                fragment_offset = Some(ipv4.fragments_offset());
                let df = ipv4.dont_fragment();
                let mf = ipv4.more_fragments();
                let frag_offset_val = ipv4.fragments_offset();
                summary = format!(
                    "TTL={} ID=0x{:04x} Flags={}{} Offset={}",
                    ipv4.ttl(), ipv4.identification(),
                    if df { "DF " } else { "" },
                    if mf { "MF" } else { "" },
                    frag_offset_val
                );

                match ipv4.protocol() {
                    x if x == etherparse::IpNumber::Tcp as u8 => protocol = ProtocolType::TCP,
                    x if x == etherparse::IpNumber::Udp as u8 => protocol = ProtocolType::UDP,
                    x if x == etherparse::IpNumber::Icmp as u8 => protocol = ProtocolType::ICMP,
                    _ => {}
                }
            }
            etherparse::InternetSlice::Ipv6(ipv6, exts) => {
                src_addr = format!("{}", ipv6.source_addr());
                dst_addr = format!("{}", ipv6.destination_addr());
                ttl = Some(ipv6.hop_limit());
                protocol = ProtocolType::IPv6;
                summary = format!("HopLimit={}", ipv6.hop_limit());

                if exts.is_fragmenting_payload() {
                    summary.push_str(" Fragmented");
                }

                match ipv6.next_header() {
                    x if x == etherparse::IpNumber::Tcp as u8 => protocol = ProtocolType::TCP,
                    x if x == etherparse::IpNumber::Udp as u8 => protocol = ProtocolType::UDP,
                    x if x == etherparse::IpNumber::Icmp as u8 => protocol = ProtocolType::ICMP,
                    _ => {}
                }
            }
        }
    }

    if let Some(transport) = &packet.transport {
        match transport {
            etherparse::TransportSlice::Tcp(tcp) => {
                src_port = Some(tcp.source_port());
                dst_port = Some(tcp.destination_port());
                window_size = Some(tcp.window_size());
                let flags = TcpFlags::from_bits(
                    (tcp.fin() as u8) | (tcp.syn() as u8 * 2) | (tcp.rst() as u8 * 4)
                        | (tcp.psh() as u8 * 8) | (tcp.ack() as u8 * 16) | (tcp.urg() as u8 * 32),
                );
                tcp_flags = Some(flags.to_string_flags());
                summary = format!(
                    "{} -> {} Seq={} Ack={} Win={} [{}]",
                    tcp.source_port(),
                    tcp.destination_port(),
                    tcp.sequence_number(),
                    tcp.acknowledgment_number(),
                    tcp.window_size(),
                    flags.to_string_flags()
                );
            }
            etherparse::TransportSlice::Udp(udp) => {
                src_port = Some(udp.source_port());
                dst_port = Some(udp.destination_port());
                summary = format!(
                    "{} -> {} Len={}",
                    udp.source_port(), udp.destination_port(),
                    udp.length()
                );
            }
            etherparse::TransportSlice::Icmpv4(icmp) => {
                summary = format!(
                    "Type={} Code={} Checksum={}",
                    icmp.type_u8(), icmp.code_u8(), icmp.checksum()
                );
            }
            etherparse::TransportSlice::Icmpv6(icmp) => {
                summary = format!(
                    "Type={} Code={} Checksum={}",
                    icmp.type_u8(), icmp.code_u8(), icmp.checksum()
                );
            }
            etherparse::TransportSlice::Unknown(_) => {}
        }
    }

    let app_data = packet.payload;
    if !app_data.is_empty() {
        let detected = detect_application_protocol(app_data, packet);
        if detected != ProtocolType::Unknown {
            protocol = detected;
        }
        match detected {
            ProtocolType::HTTP => {
                if let Some(http_summary) = parse_http_summary(app_data) {
                    summary = http_summary;
                }
            }
            ProtocolType::DNS => {
                if let Some(dns_summary) = parse_dns_summary(app_data) {
                    summary = dns_summary;
                }
            }
            ProtocolType::TLS => {
                if let Some(tls_summary) = parse_tls_summary(app_data) {
                    summary = tls_summary;
                }
            }
            _ => {}
        }
    }

    (src_addr, src_port, dst_addr, dst_port, protocol, summary, ttl, window_size, tcp_flags, ip_id, fragment_offset)
}

fn format_mac(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn format_mac_arr(mac: [u8; 6]) -> String {
    format_mac(&mac)
}

fn detect_application_protocol(data: &[u8], packet: &SlicedPacket) -> ProtocolType {
    if data.is_empty() {
        return ProtocolType::Unknown;
    }

    let is_tcp = matches!(packet.transport, Some(etherparse::TransportSlice::Tcp(_)));
    let is_udp = matches!(packet.transport, Some(etherparse::TransportSlice::Udp(_)));

    if is_tcp {
        if data.len() >= 3 {
            let prefix = &data[..3.min(data.len())];
            if prefix == b"GET" || prefix == b"POS" || prefix == b"PUT" || prefix == b"DEL"
                || prefix == b"HEA" || prefix == b"PAT" || prefix == b"OPT" || prefix == b"CON"
                || prefix == b"TRA"
            {
                return ProtocolType::HTTP;
            }
        }
        if data.len() >= 5 && &data[..5] == b"HTTP/" {
            return ProtocolType::HTTP;
        }
        if let Some(etherparse::TransportSlice::Tcp(tcp)) = &packet.transport {
            if data[0] == 0x16 || data[0] == 0x15 || data[0] == 0x14 || data[0] == 0x17 {
                if tcp.destination_port() == 443 || tcp.source_port() == 443
                    || tcp.destination_port() == 8443 || tcp.source_port() == 8443
                {
                    return ProtocolType::TLS;
                }
            }
        }
        if data.len() >= 6 && data[0] == 0x16 {
            if data[5] == 0x01 || data[5] == 0x02 || data[5] == 0x0b || data[5] == 0x0c {
                return ProtocolType::TLS;
            }
        }
    }

    if is_udp {
        if let Some(etherparse::TransportSlice::Udp(udp)) = &packet.transport {
            if udp.destination_port() == 53 || udp.source_port() == 53 {
                return ProtocolType::DNS;
            }
        }
    }

    ProtocolType::Unknown
}

fn parse_http_summary(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    let first_line = text.lines().next()?;

    if first_line.starts_with("HTTP/") {
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            return Some(format!("HTTP {} {}", parts[1], parts.get(2).unwrap_or(&"")));
        }
    } else {
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            return Some(format!("{} {}", parts[0], parts[1]));
        }
    }
    Some(first_line.to_string())
}

fn parse_dns_summary(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qr = (flags >> 15) & 1;
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);

    let domain = parse_dns_name(data, 12).unwrap_or_default();

    if qr == 0 {
        Some(format!("Query: {} ({} questions)", domain, qdcount))
    } else {
        Some(format!("Response: {} ({} answers)", domain, ancount))
    }
}

fn parse_dns_name(data: &[u8], offset: usize) -> Option<String> {
    let mut pos = offset;
    let mut name = String::new();
    let mut jumped = false;
    let mut _jump_pos = 0;

    loop {
        if pos >= data.len() {
            break;
        }
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if !jumped {
                _jump_pos = pos + 2;
            }
            jumped = true;
            if pos + 1 >= data.len() {
                break;
            }
            pos = (((data[pos] & 0x3F) as usize) << 8) | (data[pos + 1] as usize);
            continue;
        }
        if pos + len + 1 > data.len() {
            break;
        }
        if !name.is_empty() {
            name.push('.');
        }
        let label = String::from_utf8_lossy(&data[pos + 1..pos + 1 + len]);
        name.push_str(&label);
        pos += len + 1;
    }

    Some(name)
}

fn parse_tls_summary(data: &[u8]) -> Option<String> {
    if data.len() < 6 {
        return None;
    }
    if data[0] != 0x16 && data[0] != 0x15 && data[0] != 0x14 && data[0] != 0x17 {
        return None;
    }

    let record_type = match data[0] {
        0x14 => "ChangeCipherSpec",
        0x15 => "Alert",
        0x16 => "Handshake",
        0x17 => "Application Data",
        _ => "Unknown",
    };

    let version = match u16::from_be_bytes([data[1], data[2]]) {
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown",
    };

    let length = u16::from_be_bytes([data[3], data[4]]);

    if data[0] == 0x16 && data.len() > 5 {
        let handshake_type = match data[5] {
            0x01 => "ClientHello",
            0x02 => "ServerHello",
            0x0b => "Certificate",
            0x0c => "ServerKeyExchange",
            0x0e => "ServerHelloDone",
            0x10 => "ClientKeyExchange",
            0x14 => "Finished",
            _ => "Unknown",
        };
        Some(format!("TLS {} {} {} len={}", version, record_type, handshake_type, length))
    } else {
        Some(format!("TLS {} {} len={}", version, record_type, length))
    }
}

fn parse_ethernet_layer(link: &etherparse::LinkSlice) -> ProtocolLayer {
    match link {
        etherparse::LinkSlice::Ethernet2(eth) => {
            let mut fields = Vec::new();
            fields.push(FieldEntry {
                name: "Source MAC".into(),
                value: format_mac_arr(eth.source()),
                byte_range: (0, 6),
            });
            fields.push(FieldEntry {
                name: "Destination MAC".into(),
                value: format_mac_arr(eth.destination()),
                byte_range: (6, 12),
            });
            fields.push(FieldEntry {
                name: "EtherType".into(),
                value: format!("0x{:04x}", eth.ether_type()),
                byte_range: (12, 14),
            });
            ProtocolLayer {
                protocol: "Ethernet II".into(),
                fields,
                byte_range: (0, 14),
            }
        }
    }
}

fn parse_vlan_layer(vlan: &etherparse::VlanSlice) -> ProtocolLayer {
    let header = vlan.to_header();
    let mut fields = Vec::new();
    match &header {
        etherparse::VlanHeader::Single(sv) => {
            fields.push(FieldEntry { name: "VLAN ID".into(), value: format!("{}", sv.vlan_identifier), byte_range: (0, 0) });
            fields.push(FieldEntry { name: "EtherType".into(), value: format!("0x{:04x}", sv.ether_type), byte_range: (0, 0) });
        }
        etherparse::VlanHeader::Double(dv) => {
            fields.push(FieldEntry { name: "Outer VLAN ID".into(), value: format!("{}", dv.outer.vlan_identifier), byte_range: (0, 0) });
            fields.push(FieldEntry { name: "Inner VLAN ID".into(), value: format!("{}", dv.inner.vlan_identifier), byte_range: (0, 0) });
        }
    }
    ProtocolLayer {
        protocol: "VLAN".into(),
        fields,
        byte_range: (0, 0),
    }
}

fn parse_ip_layer(ip: &etherparse::InternetSlice) -> ProtocolLayer {
    match ip {
        etherparse::InternetSlice::Ipv4(ipv4, _exts) => {
            let mut fields = Vec::new();
            fields.push(FieldEntry { name: "Version".into(), value: "4".into(), byte_range: (0, 1) });
            fields.push(FieldEntry { name: "Header Length".into(), value: format!("{} bytes", ipv4.ihl() * 4), byte_range: (0, 1) });
            fields.push(FieldEntry { name: "Total Length".into(), value: format!("{}", ipv4.total_len()), byte_range: (2, 4) });
            fields.push(FieldEntry { name: "Identification".into(), value: format!("0x{:04x}", ipv4.identification()), byte_range: (4, 6) });
            fields.push(FieldEntry {
                name: "Flags".into(),
                value: format!("{}{}", if ipv4.dont_fragment() { "DF " } else { "" }, if ipv4.more_fragments() { "MF" } else { "" }),
                byte_range: (6, 8),
            });
            fields.push(FieldEntry { name: "Fragment Offset".into(), value: format!("{}", ipv4.fragments_offset()), byte_range: (6, 8) });
            fields.push(FieldEntry { name: "TTL".into(), value: format!("{}", ipv4.ttl()), byte_range: (8, 9) });
            fields.push(FieldEntry { name: "Protocol".into(), value: format!("{}", ipv4.protocol()), byte_range: (9, 10) });
            fields.push(FieldEntry { name: "Header Checksum".into(), value: format!("0x{:04x}", ipv4.header_checksum()), byte_range: (10, 12) });
            fields.push(FieldEntry { name: "Source IP".into(), value: format!("{}", ipv4.source_addr()), byte_range: (12, 16) });
            fields.push(FieldEntry { name: "Destination IP".into(), value: format!("{}", ipv4.destination_addr()), byte_range: (16, 20) });
            ProtocolLayer {
                protocol: "Internet Protocol Version 4".into(),
                fields,
                byte_range: (14, 34),
            }
        }
        etherparse::InternetSlice::Ipv6(ipv6, _exts) => {
            let mut fields = Vec::new();
            fields.push(FieldEntry { name: "Version".into(), value: "6".into(), byte_range: (0, 1) });
            fields.push(FieldEntry { name: "Traffic Class".into(), value: format!("0x{:02x}", ipv6.traffic_class()), byte_range: (0, 2) });
            fields.push(FieldEntry { name: "Flow Label".into(), value: format!("0x{:05x}", ipv6.flow_label()), byte_range: (0, 4) });
            fields.push(FieldEntry { name: "Payload Length".into(), value: format!("{}", ipv6.payload_length()), byte_range: (4, 6) });
            fields.push(FieldEntry { name: "Next Header".into(), value: format!("{}", ipv6.next_header()), byte_range: (6, 7) });
            fields.push(FieldEntry { name: "Hop Limit".into(), value: format!("{}", ipv6.hop_limit()), byte_range: (7, 8) });
            fields.push(FieldEntry { name: "Source IP".into(), value: format!("{}", ipv6.source_addr()), byte_range: (8, 24) });
            fields.push(FieldEntry { name: "Destination IP".into(), value: format!("{}", ipv6.destination_addr()), byte_range: (24, 40) });
            ProtocolLayer {
                protocol: "Internet Protocol Version 6".into(),
                fields,
                byte_range: (14, 54),
            }
        }
    }
}

fn parse_transport_layer(transport: &etherparse::TransportSlice) -> ProtocolLayer {
    match transport {
        etherparse::TransportSlice::Tcp(tcp) => {
            let flags = TcpFlags::from_bits(
                (tcp.fin() as u8) | (tcp.syn() as u8 * 2) | (tcp.rst() as u8 * 4)
                    | (tcp.psh() as u8 * 8) | (tcp.ack() as u8 * 16) | (tcp.urg() as u8 * 32),
            );
            let mut fields = Vec::new();
            fields.push(FieldEntry { name: "Source Port".into(), value: format!("{}", tcp.source_port()), byte_range: (0, 2) });
            fields.push(FieldEntry { name: "Destination Port".into(), value: format!("{}", tcp.destination_port()), byte_range: (2, 4) });
            fields.push(FieldEntry { name: "Sequence Number".into(), value: format!("{}", tcp.sequence_number()), byte_range: (4, 8) });
            fields.push(FieldEntry { name: "Acknowledgment Number".into(), value: format!("{}", tcp.acknowledgment_number()), byte_range: (8, 12) });
            fields.push(FieldEntry { name: "Data Offset".into(), value: format!("{} bytes", tcp.data_offset() as usize * 4), byte_range: (12, 13) });
            fields.push(FieldEntry { name: "Flags".into(), value: flags.to_string_flags(), byte_range: (13, 14) });
            fields.push(FieldEntry { name: "Window Size".into(), value: format!("{}", tcp.window_size()), byte_range: (14, 16) });
            fields.push(FieldEntry { name: "Checksum".into(), value: format!("0x{:04x}", tcp.checksum()), byte_range: (16, 18) });
            fields.push(FieldEntry { name: "Urgent Pointer".into(), value: format!("{}", tcp.urgent_pointer()), byte_range: (18, 20) });
            ProtocolLayer {
                protocol: "Transmission Control Protocol".into(),
                fields,
                byte_range: (34, 54),
            }
        }
        etherparse::TransportSlice::Udp(udp) => {
            let mut fields = Vec::new();
            fields.push(FieldEntry { name: "Source Port".into(), value: format!("{}", udp.source_port()), byte_range: (0, 2) });
            fields.push(FieldEntry { name: "Destination Port".into(), value: format!("{}", udp.destination_port()), byte_range: (2, 4) });
            fields.push(FieldEntry { name: "Length".into(), value: format!("{}", udp.length()), byte_range: (4, 6) });
            fields.push(FieldEntry { name: "Checksum".into(), value: format!("0x{:04x}", udp.checksum()), byte_range: (6, 8) });
            ProtocolLayer {
                protocol: "User Datagram Protocol".into(),
                fields,
                byte_range: (34, 42),
            }
        }
        etherparse::TransportSlice::Icmpv4(icmp) => {
            let type_name = match icmp.type_u8() {
                0 => "Echo Reply",
                3 => "Destination Unreachable",
                5 => "Redirect",
                8 => "Echo Request",
                11 => "Time Exceeded",
                _ => "Unknown",
            };
            let mut fields = Vec::new();
            fields.push(FieldEntry { name: "Type".into(), value: format!("{} ({})", icmp.type_u8(), type_name), byte_range: (0, 1) });
            fields.push(FieldEntry { name: "Code".into(), value: format!("{}", icmp.code_u8()), byte_range: (1, 2) });
            fields.push(FieldEntry { name: "Checksum".into(), value: format!("0x{:04x}", icmp.checksum()), byte_range: (2, 4) });
            ProtocolLayer {
                protocol: "Internet Control Message Protocol".into(),
                fields,
                byte_range: (34, 38),
            }
        }
        etherparse::TransportSlice::Icmpv6(icmp) => {
            let mut fields = Vec::new();
            fields.push(FieldEntry { name: "Type".into(), value: format!("{}", icmp.type_u8()), byte_range: (0, 1) });
            fields.push(FieldEntry { name: "Code".into(), value: format!("{}", icmp.code_u8()), byte_range: (1, 2) });
            fields.push(FieldEntry { name: "Checksum".into(), value: format!("0x{:04x}", icmp.checksum()), byte_range: (2, 4) });
            ProtocolLayer {
                protocol: "ICMPv6".into(),
                fields,
                byte_range: (54, 58),
            }
        }
        etherparse::TransportSlice::Unknown(proto) => {
            ProtocolLayer {
                protocol: format!("Unknown Transport ({})", proto),
                fields: vec![],
                byte_range: (0, 0),
            }
        }
    }
}

fn parse_application_layer(
    data: &[u8],
    packet: &SlicedPacket,
) -> Option<ProtocolLayer> {
    let detected = detect_application_protocol(data, packet);

    match detected {
        ProtocolType::HTTP => {
            let text = String::from_utf8_lossy(data);
            let mut fields = Vec::new();
            let first_line = text.lines().next().unwrap_or("");

            if first_line.starts_with("HTTP/") {
                let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
                if parts.len() >= 2 {
                    fields.push(FieldEntry { name: "Status Code".into(), value: parts[1].into(), byte_range: (0, first_line.len()) });
                    if parts.len() >= 3 {
                        fields.push(FieldEntry { name: "Status Text".into(), value: parts[2].into(), byte_range: (0, first_line.len()) });
                    }
                }
            } else {
                let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
                if parts.len() >= 2 {
                    fields.push(FieldEntry { name: "Method".into(), value: parts[0].into(), byte_range: (0, first_line.len()) });
                    fields.push(FieldEntry { name: "URL".into(), value: parts[1].into(), byte_range: (0, first_line.len()) });
                }
            }

            for line in text.lines().skip(1) {
                if line.is_empty() {
                    break;
                }
                if let Some(colon_pos) = line.find(':') {
                    let key = &line[..colon_pos];
                    let val = line[colon_pos + 1..].trim();
                    fields.push(FieldEntry { name: key.into(), value: val.into(), byte_range: (0, 0) });
                }
            }

            Some(ProtocolLayer {
                protocol: "Hypertext Transfer Protocol".into(),
                fields,
                byte_range: (0, data.len()),
            })
        }
        ProtocolType::DNS => {
            let mut fields = Vec::new();
            if data.len() >= 12 {
                let flags = u16::from_be_bytes([data[2], data[3]]);
                let qr = (flags >> 15) & 1;
                let opcode = (flags >> 11) & 0xF;
                let rcode = flags & 0xF;
                let qdcount = u16::from_be_bytes([data[4], data[5]]);
                let ancount = u16::from_be_bytes([data[6], data[7]]);

                fields.push(FieldEntry { name: "Transaction ID".into(), value: format!("0x{:04x}", u16::from_be_bytes([data[0], data[1]])), byte_range: (0, 2) });
                fields.push(FieldEntry { name: "Flags".into(), value: format!("QR={} Opcode={} RCODE={}", qr, opcode, rcode), byte_range: (2, 4) });
                fields.push(FieldEntry { name: "Questions".into(), value: format!("{}", qdcount), byte_range: (4, 6) });
                fields.push(FieldEntry { name: "Answers".into(), value: format!("{}", ancount), byte_range: (6, 8) });

                if let Some(domain) = parse_dns_name(data, 12) {
                    fields.push(FieldEntry { name: "Query Name".into(), value: domain, byte_range: (12, data.len()) });
                }

                let qtype = if data.len() > 14 {
                    let mut pos = 12;
                    while pos < data.len() && data[pos] != 0 {
                        let label_len = data[pos] as usize;
                        pos += label_len + 1;
                    }
                    pos += 1;
                    if pos + 4 <= data.len() {
                        let qt = u16::from_be_bytes([data[pos], data[pos + 1]]);
                        Some(match qt {
                            1 => "A",
                            2 => "NS",
                            5 => "CNAME",
                            6 => "SOA",
                            12 => "PTR",
                            15 => "MX",
                            16 => "TXT",
                            28 => "AAAA",
                            33 => "SRV",
                            255 => "ANY",
                            _ => "Unknown",
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(qt) = qtype {
                    fields.push(FieldEntry { name: "Query Type".into(), value: qt.into(), byte_range: (0, 0) });
                }
            }

            Some(ProtocolLayer {
                protocol: "Domain Name System".into(),
                fields,
                byte_range: (0, data.len()),
            })
        }
        ProtocolType::TLS => {
            let mut fields = Vec::new();

            if data.len() >= 5 {
                let record_type = match data[0] {
                    0x14 => "ChangeCipherSpec",
                    0x15 => "Alert",
                    0x16 => "Handshake",
                    0x17 => "Application Data",
                    _ => "Unknown",
                };

                let version = match u16::from_be_bytes([data[1], data[2]]) {
                    0x0301 => "TLS 1.0",
                    0x0302 => "TLS 1.1",
                    0x0303 => "TLS 1.2",
                    0x0304 => "TLS 1.3",
                    _ => "Unknown",
                };

                let length = u16::from_be_bytes([data[3], data[4]]);

                fields.push(FieldEntry { name: "Content Type".into(), value: record_type.into(), byte_range: (0, 1) });
                fields.push(FieldEntry { name: "Version".into(), value: version.into(), byte_range: (1, 3) });
                fields.push(FieldEntry { name: "Length".into(), value: format!("{}", length), byte_range: (3, 5) });

                if data[0] == 0x16 && data.len() > 5 {
                    let handshake_type = match data[5] {
                        0x01 => "ClientHello",
                        0x02 => "ServerHello",
                        0x0b => "Certificate",
                        0x0c => "ServerKeyExchange",
                        0x0e => "ServerHelloDone",
                        0x10 => "ClientKeyExchange",
                        0x14 => "Finished",
                        _ => "Unknown",
                    };
                    fields.push(FieldEntry { name: "Handshake Type".into(), value: handshake_type.into(), byte_range: (5, 6) });

                    if data[5] == 0x02 && data.len() > 46 {
                        let server_version = u16::from_be_bytes([data[10], data[11]]);
                        let sv = match server_version {
                            0x0303 => "TLS 1.2",
                            0x0304 => "TLS 1.3",
                            _ => "Unknown",
                        };
                        fields.push(FieldEntry { name: "Server Version".into(), value: sv.into(), byte_range: (10, 12) });

                        if data.len() > 46 {
                            let session_id_len = data[44] as usize;
                            let cipher_start = 45 + session_id_len;
                            if cipher_start + 2 <= data.len() {
                                let cipher_len = u16::from_be_bytes([data[cipher_start], data[cipher_start + 1]]) as usize;
                                fields.push(FieldEntry {
                                    name: "Cipher Suite Count".into(),
                                    value: format!("{}", cipher_len / 2),
                                    byte_range: (cipher_start, cipher_start + 2),
                                });
                            }
                        }
                    }

                    if data[5] == 0x01 && data.len() > 42 {
                        let cipher_len = u16::from_be_bytes([data[43], data[44]]) as usize;
                        fields.push(FieldEntry {
                            name: "Cipher Suite Count".into(),
                            value: format!("{}", cipher_len / 2),
                            byte_range: (43, 45),
                        });

                        let cipher_start = 45;
                        let cipher_end = cipher_start + cipher_len;
                        if cipher_end <= data.len() {
                            let mut suites = Vec::new();
                            for i in (cipher_start..cipher_end).step_by(2) {
                                if i + 1 < data.len() {
                                    let suite = u16::from_be_bytes([data[i], data[i + 1]]);
                                    suites.push(format_cipher_suite(suite));
                                }
                            }
                            if !suites.is_empty() {
                                fields.push(FieldEntry {
                                    name: "Cipher Suites".into(),
                                    value: suites.join(", "),
                                    byte_range: (cipher_start, cipher_end),
                                });
                            }
                        }
                    }
                }
            }

            Some(ProtocolLayer {
                protocol: "Transport Layer Security".into(),
                fields,
                byte_range: (0, data.len()),
            })
        }
        _ => None,
    }
}

fn format_cipher_suite(suite: u16) -> String {
    match suite {
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA".into(),
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA".into(),
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA".into(),
        0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256".into(),
        0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384".into(),
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".into(),
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into(),
        0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".into(),
        0xCCA9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".into(),
        0x1301 => "TLS_AES_128_GCM_SHA256".into(),
        0x1302 => "TLS_AES_256_GCM_SHA384".into(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".into(),
        _ => format!("0x{:04x}", suite),
    }
}
