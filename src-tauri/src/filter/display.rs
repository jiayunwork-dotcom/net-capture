use crate::models::{PacketMetadata, ProtocolType};

#[derive(Debug, Clone)]
pub enum FilterNode {
    Protocol(ProtocolType),
    SrcIp(String),
    DstIp(String),
    AnyIp(String),
    SrcPort(u16),
    DstPort(u16),
    AnyPort(u16),
    Contains(String),
    And(Box<FilterNode>, Box<FilterNode>),
    Or(Box<FilterNode>, Box<FilterNode>),
    Not(Box<FilterNode>),
    True,
    False,
}

pub fn parse_filter(expr: &str) -> Result<FilterNode, String> {
    let tokens = tokenize(expr)?;
    let (node, _) = parse_or(&tokens, 0)?;
    Ok(node)
}

fn tokenize(expr: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = expr.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c == '(' {
            tokens.push(Token::LParen);
            chars.next();
        } else if c == ')' {
            tokens.push(Token::RParen);
            chars.next();
        } else {
            let mut word = String::new();
            while let Some(&wc) = chars.peek() {
                if wc.is_whitespace() || wc == '(' || wc == ')' {
                    break;
                }
                word.push(wc);
                chars.next();
            }

            let lower = word.to_lowercase();
            match lower.as_str() {
                "and" | "&&" => tokens.push(Token::And),
                "or" | "||" => tokens.push(Token::Or),
                "not" | "!" => tokens.push(Token::Not),
                "http" => tokens.push(Token::Protocol(ProtocolType::HTTP)),
                "dns" => tokens.push(Token::Protocol(ProtocolType::DNS)),
                "tcp" => tokens.push(Token::Protocol(ProtocolType::TCP)),
                "udp" => tokens.push(Token::Protocol(ProtocolType::UDP)),
                "tls" | "ssl" => tokens.push(Token::Protocol(ProtocolType::TLS)),
                "arp" => tokens.push(Token::Protocol(ProtocolType::ARP)),
                "icmp" => tokens.push(Token::Protocol(ProtocolType::ICMP)),
                _ => {
                    if let Some(rest) = word.strip_prefix("ip.src==") {
                        tokens.push(Token::SrcIp(rest.to_string()));
                    } else if let Some(rest) = word.strip_prefix("ip.dst==") {
                        tokens.push(Token::DstIp(rest.to_string()));
                    } else if let Some(rest) = word.strip_prefix("ip.addr==") {
                        tokens.push(Token::AnyIp(rest.to_string()));
                    } else if let Some(rest) = word.strip_prefix("ip.src=") {
                        tokens.push(Token::SrcIp(rest.to_string()));
                    } else if let Some(rest) = word.strip_prefix("ip.dst=") {
                        tokens.push(Token::DstIp(rest.to_string()));
                    } else if let Some(rest) = word.strip_prefix("tcp.port==") {
                        if let Ok(port) = rest.parse::<u16>() {
                            tokens.push(Token::AnyPort(port));
                        }
                    } else if let Some(rest) = word.strip_prefix("tcp.srcport==") {
                        if let Ok(port) = rest.parse::<u16>() {
                            tokens.push(Token::SrcPort(port));
                        }
                    } else if let Some(rest) = word.strip_prefix("tcp.dstport==") {
                        if let Ok(port) = rest.parse::<u16>() {
                            tokens.push(Token::DstPort(port));
                        }
                    } else if let Some(rest) = word.strip_prefix("udp.port==") {
                        if let Ok(port) = rest.parse::<u16>() {
                            tokens.push(Token::AnyPort(port));
                        }
                    } else if let Some(rest) = word.strip_prefix("udp.srcport==") {
                        if let Ok(port) = rest.parse::<u16>() {
                            tokens.push(Token::SrcPort(port));
                        }
                    } else if let Some(rest) = word.strip_prefix("udp.dstport==") {
                        if let Ok(port) = rest.parse::<u16>() {
                            tokens.push(Token::DstPort(port));
                        }
                    } else if let Some(rest) = word.strip_prefix("port==") {
                        if let Ok(port) = rest.parse::<u16>() {
                            tokens.push(Token::AnyPort(port));
                        }
                    } else if let Some(rest) = word.strip_prefix("contains") {
                        let val = rest.trim_start_matches('"').trim_end_matches('"').trim();
                        tokens.push(Token::Contains(val.to_string()));
                    } else if word.starts_with('"') && word.ends_with('"') {
                        let inner = &word[1..word.len()-1];
                        tokens.push(Token::Contains(inner.to_string()));
                    } else if word == "ip" {
                        tokens.push(Token::Protocol(ProtocolType::IPv4));
                    } else if word == "ipv6" {
                        tokens.push(Token::Protocol(ProtocolType::IPv6));
                    } else if word == "eth" || word == "ethernet" {
                        tokens.push(Token::Protocol(ProtocolType::Ethernet));
                    } else {
                        tokens.push(Token::Unknown(word));
                    }
                }
            }
        }
    }

    Ok(tokens)
}

#[derive(Debug, Clone)]
enum Token {
    Protocol(ProtocolType),
    SrcIp(String),
    DstIp(String),
    AnyIp(String),
    SrcPort(u16),
    DstPort(u16),
    AnyPort(u16),
    Contains(String),
    And,
    Or,
    Not,
    LParen,
    RParen,
    Unknown(String),
}

fn parse_or(tokens: &[Token], pos: usize) -> Result<(FilterNode, usize), String> {
    let (left, mut pos) = parse_and(tokens, pos)?;
    while pos < tokens.len() {
        match &tokens[pos] {
            Token::Or => {
                pos += 1;
                let (right, new_pos) = parse_and(tokens, pos)?;
                pos = new_pos;
                return Ok((FilterNode::Or(Box::new(left), Box::new(right)), pos));
            }
            _ => break,
        }
    }
    Ok((left, pos))
}

fn parse_and(tokens: &[Token], pos: usize) -> Result<(FilterNode, usize), String> {
    let (left, mut pos) = parse_not(tokens, pos)?;
    while pos < tokens.len() {
        match &tokens[pos] {
            Token::And => {
                pos += 1;
                let (right, new_pos) = parse_not(tokens, pos)?;
                pos = new_pos;
                return Ok((FilterNode::And(Box::new(left), Box::new(right)), pos));
            }
            Token::RParen => break,
            _ => break,
        }
    }
    Ok((left, pos))
}

fn parse_not(tokens: &[Token], pos: usize) -> Result<(FilterNode, usize), String> {
    if pos < tokens.len() {
        if matches!(&tokens[pos], Token::Not) {
            let pos = pos + 1;
            let (node, new_pos) = parse_primary(tokens, pos)?;
            return Ok((FilterNode::Not(Box::new(node)), new_pos));
        }
    }
    parse_primary(tokens, pos)
}

fn parse_primary(tokens: &[Token], pos: usize) -> Result<(FilterNode, usize), String> {
    if pos >= tokens.len() {
        return Ok((FilterNode::True, pos));
    }

    match &tokens[pos] {
        Token::LParen => {
            let (node, pos) = parse_or(tokens, pos + 1)?;
            if pos < tokens.len() && matches!(&tokens[pos], Token::RParen) {
                Ok((node, pos + 1))
            } else {
                Ok((node, pos))
            }
        }
        Token::Protocol(p) => Ok((FilterNode::Protocol(p.clone()), pos + 1)),
        Token::SrcIp(ip) => Ok((FilterNode::SrcIp(ip.clone()), pos + 1)),
        Token::DstIp(ip) => Ok((FilterNode::DstIp(ip.clone()), pos + 1)),
        Token::AnyIp(ip) => Ok((FilterNode::AnyIp(ip.clone()), pos + 1)),
        Token::SrcPort(p) => Ok((FilterNode::SrcPort(*p), pos + 1)),
        Token::DstPort(p) => Ok((FilterNode::DstPort(*p), pos + 1)),
        Token::AnyPort(p) => Ok((FilterNode::AnyPort(*p), pos + 1)),
        Token::Contains(s) => Ok((FilterNode::Contains(s.clone()), pos + 1)),
        _ => Ok((FilterNode::False, pos + 1)),
    }
}

pub fn evaluate_filter(node: &FilterNode, meta: &PacketMetadata) -> bool {
    match node {
        FilterNode::Protocol(p) => meta.protocol == *p,
        FilterNode::SrcIp(ip) => meta.src_addr == *ip,
        FilterNode::DstIp(ip) => meta.dst_addr == *ip,
        FilterNode::AnyIp(ip) => meta.src_addr == *ip || meta.dst_addr == *ip,
        FilterNode::SrcPort(p) => meta.src_port == Some(*p),
        FilterNode::DstPort(p) => meta.dst_port == Some(*p),
        FilterNode::AnyPort(p) => meta.src_port == Some(*p) || meta.dst_port == Some(*p),
        FilterNode::Contains(keyword) => {
            let lower = meta.summary.to_lowercase();
            lower.contains(&keyword.to_lowercase())
        }
        FilterNode::And(l, r) => evaluate_filter(l, meta) && evaluate_filter(r, meta),
        FilterNode::Or(l, r) => evaluate_filter(l, meta) || evaluate_filter(r, meta),
        FilterNode::Not(n) => !evaluate_filter(n, meta),
        FilterNode::True => true,
        FilterNode::False => false,
    }
}

pub fn filter_packets(
    packets: &[PacketMetadata],
    filter_expr: &str,
) -> Result<Vec<PacketMetadata>, String> {
    if filter_expr.trim().is_empty() {
        return Ok(packets.to_vec());
    }

    let node = parse_filter(filter_expr)?;
    Ok(packets.iter().filter(|p| evaluate_filter(&node, p)).cloned().collect())
}
