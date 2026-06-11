use super::models::*;

pub struct ExpressionParser {
    input: Vec<char>,
    pos: usize,
}

impl ExpressionParser {
    pub fn new(input: &str) -> Self {
        Self {
            input: input.chars().collect(),
            pos: 0,
        }
    }

    pub fn parse(&mut self) -> Result<ConditionNode, ParseError> {
        self.skip_whitespace();
        let node = self.parse_or()?;
        self.skip_whitespace();
        if self.pos < self.input.len() {
            return Err(ParseError {
                message: format!("Unexpected character '{}'", self.input[self.pos]),
                position: Some(self.pos),
            });
        }
        Ok(node)
    }

    fn parse_or(&mut self) -> Result<ConditionNode, ParseError> {
        let mut left = self.parse_and()?;
        self.skip_whitespace();

        while self.match_keyword("OR") || self.match_token('|') {
            self.skip_whitespace();
            let right = self.parse_and()?;
            match left {
                ConditionNode::Or { ref mut children } => {
                    children.push(right);
                }
                _ => {
                    left = ConditionNode::Or {
                        children: vec![left, right],
                    };
                }
            }
            self.skip_whitespace();
        }

        Ok(left)
    }

    fn parse_and(&mut self) -> Result<ConditionNode, ParseError> {
        let mut left = self.parse_not()?;
        self.skip_whitespace();

        while self.match_keyword("AND") || self.match_token('&') {
            self.skip_whitespace();
            let right = self.parse_not()?;
            match left {
                ConditionNode::And { ref mut children } => {
                    children.push(right);
                }
                _ => {
                    left = ConditionNode::And {
                        children: vec![left, right],
                    };
                }
            }
            self.skip_whitespace();
        }

        Ok(left)
    }

    fn parse_not(&mut self) -> Result<ConditionNode, ParseError> {
        if self.match_keyword("NOT") || self.match_token('!') {
            self.skip_whitespace();
            let child = self.parse_not()?;
            Ok(ConditionNode::Not {
                child: Box::new(child),
            })
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<ConditionNode, ParseError> {
        self.skip_whitespace();

        if self.match_token('(') {
            self.skip_whitespace();
            let node = self.parse_or()?;
            self.skip_whitespace();
            if !self.match_token(')') {
                return Err(ParseError {
                    message: "Expected ')'".to_string(),
                    position: Some(self.pos),
                });
            }
            return Ok(node);
        }

        self.parse_condition_atom()
    }

    fn parse_condition_atom(&mut self) -> Result<ConditionNode, ParseError> {
        let start_pos = self.pos;
        let name = self.parse_identifier()?;

        match name.to_lowercase().as_str() {
            "protocol" => self.parse_protocol_match(),
            "src_ip" | "srcip" => self.parse_ip_match(IpField::Src),
            "dst_ip" | "dstip" => self.parse_ip_match(IpField::Dst),
            "ip" => self.parse_ip_match(IpField::Either),
            "src_port" | "srcport" => self.parse_port_range(PortField::Src),
            "dst_port" | "dstport" => self.parse_port_range(PortField::Dst),
            "port" => self.parse_port_range(PortField::Either),
            "length" | "len" => self.parse_packet_length(),
            "tcp_flags" | "flags" => self.parse_tcp_flags(),
            "payload" | "content" => self.parse_payload_keyword(),
            "rate" | "rate_limit" => self.parse_rate_limit(),
            "dns_blacklist" | "dns_blocklist" => self.parse_dns_blacklist(),
            _ => Err(ParseError {
                message: format!("Unknown condition: '{}'", name),
                position: Some(start_pos),
            }),
        }
    }

    fn parse_protocol_match(&mut self) -> Result<ConditionNode, ParseError> {
        self.expect_operator("==")?;
        let protocol = self.parse_string_or_identifier()?;
        Ok(ConditionNode::ProtocolMatch { protocol })
    }

    fn parse_ip_match(&mut self, field: IpField) -> Result<ConditionNode, ParseError> {
        self.expect_operator("==")?;
        let cidr = self.parse_string_or_identifier()?;
        Ok(ConditionNode::IpMatch { field, cidr })
    }

    fn parse_port_range(&mut self, field: PortField) -> Result<ConditionNode, ParseError> {
        self.expect_operator("==")?;
        let range_str = self.parse_string_or_identifier()?;
        let parts: Vec<&str> = range_str.split('-').collect();
        if parts.len() != 2 {
            return Err(ParseError {
                message: format!("Invalid port range: '{}'", range_str),
                position: Some(self.pos),
            });
        }
        let min: u16 = parts[0].parse().map_err(|_| ParseError {
            message: format!("Invalid port number: '{}'", parts[0]),
            position: None,
        })?;
        let max: u16 = parts[1].parse().map_err(|_| ParseError {
            message: format!("Invalid port number: '{}'", parts[1]),
            position: None,
        })?;
        Ok(ConditionNode::PortRange { field, min, max })
    }

    fn parse_packet_length(&mut self) -> Result<ConditionNode, ParseError> {
        let operator = self.parse_comparison_operator()?;
        let value = self.parse_number()? as u32;
        Ok(ConditionNode::PacketLength { operator, value })
    }

    fn parse_tcp_flags(&mut self) -> Result<ConditionNode, ParseError> {
        self.expect_operator("==")?;
        let flags_str = self.parse_string_or_identifier()?;
        let flags: Vec<TcpFlag> = flags_str
            .split(',')
            .filter_map(|f| match f.trim().to_uppercase().as_str() {
                "SYN" => Some(TcpFlag::SYN),
                "ACK" => Some(TcpFlag::ACK),
                "FIN" => Some(TcpFlag::FIN),
                "RST" => Some(TcpFlag::RST),
                "PSH" => Some(TcpFlag::PSH),
                "URG" => Some(TcpFlag::URG),
                _ => None,
            })
            .collect();

        let mode = FlagMatchMode::All;
        Ok(ConditionNode::TcpFlags { flags, mode })
    }

    fn parse_payload_keyword(&mut self) -> Result<ConditionNode, ParseError> {
        self.expect_operator("==")?;
        let pattern = self.parse_string()?;
        Ok(ConditionNode::PayloadKeyword {
            pattern,
            compiled: None,
        })
    }

    fn parse_rate_limit(&mut self) -> Result<ConditionNode, ParseError> {
        self.expect_token('(')?;
        let window_secs = self.parse_number()? as u32;
        self.expect_token(',')?;
        let threshold = self.parse_number()? as u32;
        self.expect_token(',')?;
        let src_ip_str = self.parse_identifier()?.to_lowercase();
        let src_ip = src_ip_str == "src" || src_ip_str == "true";
        self.expect_token(')')?;
        Ok(ConditionNode::RateLimit {
            window_secs,
            threshold,
            src_ip,
        })
    }

    fn parse_dns_blacklist(&mut self) -> Result<ConditionNode, ParseError> {
        self.expect_token('(')?;
        let mut domains = Vec::new();
        if !self.peek_token(')') {
            domains.push(self.parse_string()?);
            while self.match_token(',') {
                domains.push(self.parse_string()?);
            }
        }
        self.expect_token(')')?;
        Ok(ConditionNode::DnsBlacklist { domains })
    }

    fn parse_identifier(&mut self) -> Result<String, ParseError> {
        self.skip_whitespace();
        let start = self.pos;
        while self.pos < self.input.len() {
            let c = self.input[self.pos];
            if c.is_alphanumeric() || c == '_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            return Err(ParseError {
                message: "Expected identifier".to_string(),
                position: Some(start),
            });
        }
        Ok(self.input[start..self.pos].iter().collect())
    }

    fn parse_number(&mut self) -> Result<u64, ParseError> {
        self.skip_whitespace();
        let start = self.pos;
        while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        if start == self.pos {
            return Err(ParseError {
                message: "Expected number".to_string(),
                position: Some(start),
            });
        }
        let num_str: String = self.input[start..self.pos].iter().collect();
        num_str.parse().map_err(|_| ParseError {
            message: "Invalid number".to_string(),
            position: Some(start),
        })
    }

    fn parse_string(&mut self) -> Result<String, ParseError> {
        self.skip_whitespace();
        if self.pos >= self.input.len() {
            return Err(ParseError {
                message: "Expected string".to_string(),
                position: Some(self.pos),
            });
        }

        let quote = self.input[self.pos];
        if quote != '"' && quote != '\'' {
            return Err(ParseError {
                message: format!("Expected quote, found '{}'", quote),
                position: Some(self.pos),
            });
        }

        self.pos += 1;
        let start = self.pos;

        while self.pos < self.input.len() && self.input[self.pos] != quote {
            if self.input[self.pos] == '\\' {
                self.pos += 2;
            } else {
                self.pos += 1;
            }
        }

        if self.pos >= self.input.len() {
            return Err(ParseError {
                message: "Unterminated string".to_string(),
                position: Some(start - 1),
            });
        }

        let s: String = self.input[start..self.pos].iter().collect();
        self.pos += 1;
        Ok(s)
    }

    fn parse_string_or_identifier(&mut self) -> Result<String, ParseError> {
        self.skip_whitespace();
        if self.pos < self.input.len() {
            let c = self.input[self.pos];
            if c == '"' || c == '\'' {
                return self.parse_string();
            }
        }
        self.parse_identifier()
    }

    fn parse_comparison_operator(&mut self) -> Result<LengthOperator, ParseError> {
        self.skip_whitespace();
        if self.match_str(">=") || self.match_str("=>") {
            Ok(LengthOperator::GreaterThan)
        } else if self.match_str("<=") || self.match_str("=<") {
            Ok(LengthOperator::LessThan)
        } else if self.match_str("==") || self.match_str("=") {
            Ok(LengthOperator::Equal)
        } else if self.match_token('>') {
            Ok(LengthOperator::GreaterThan)
        } else if self.match_token('<') {
            Ok(LengthOperator::LessThan)
        } else {
            Err(ParseError {
                message: "Expected comparison operator".to_string(),
                position: Some(self.pos),
            })
        }
    }

    fn expect_operator(&mut self, op: &str) -> Result<(), ParseError> {
        self.skip_whitespace();
        if self.match_str(op) {
            Ok(())
        } else {
            Err(ParseError {
                message: format!("Expected operator '{}'", op),
                position: Some(self.pos),
            })
        }
    }

    fn expect_token(&mut self, c: char) -> Result<(), ParseError> {
        self.skip_whitespace();
        if self.match_token(c) {
            Ok(())
        } else {
            Err(ParseError {
                message: format!("Expected '{}'", c),
                position: Some(self.pos),
            })
        }
    }

    fn match_keyword(&mut self, keyword: &str) -> bool {
        self.skip_whitespace();
        let len = keyword.len();
        if self.pos + len > self.input.len() {
            return false;
        }
        let slice: String = self.input[self.pos..self.pos + len].iter().collect();
        if slice.eq_ignore_ascii_case(keyword) {
            if self.pos + len < self.input.len() {
                let next = self.input[self.pos + len];
                if next.is_alphanumeric() || next == '_' {
                    return false;
                }
            }
            self.pos += len;
            return true;
        }
        false
    }

    fn match_str(&mut self, s: &str) -> bool {
        self.skip_whitespace();
        let chars: Vec<char> = s.chars().collect();
        if self.pos + chars.len() > self.input.len() {
            return false;
        }
        for (i, &c) in chars.iter().enumerate() {
            if self.input[self.pos + i] != c {
                return false;
            }
        }
        self.pos += chars.len();
        true
    }

    fn match_token(&mut self, c: char) -> bool {
        self.skip_whitespace();
        if self.pos < self.input.len() && self.input[self.pos] == c {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn peek_token(&self, c: char) -> bool {
        let mut pos = self.pos;
        while pos < self.input.len() && self.input[pos].is_whitespace() {
            pos += 1;
        }
        pos < self.input.len() && self.input[pos] == c
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() && self.input[self.pos].is_whitespace() {
            self.pos += 1;
        }
    }
}

pub fn node_to_expression(node: &ConditionNode) -> String {
    match node {
        ConditionNode::And { children } => {
            if children.is_empty() {
                "true".to_string()
            } else {
                children
                    .iter()
                    .map(|c| format_operand(c, false))
                    .collect::<Vec<_>>()
                    .join(" AND ")
            }
        }
        ConditionNode::Or { children } => {
            if children.is_empty() {
                "false".to_string()
            } else {
                children
                    .iter()
                    .map(|c| format_operand(c, true))
                    .collect::<Vec<_>>()
                    .join(" OR ")
            }
        }
        ConditionNode::Not { child } => {
            format!("NOT {}", format_operand(child, false))
        }
        ConditionNode::ProtocolMatch { protocol } => {
            format!("protocol == \"{}\"", protocol)
        }
        ConditionNode::IpMatch { field, cidr } => {
            let field_name = match field {
                IpField::Src => "src_ip",
                IpField::Dst => "dst_ip",
                IpField::Either => "ip",
            };
            format!("{} == \"{}\"", field_name, cidr)
        }
        ConditionNode::PortRange { field, min, max } => {
            let field_name = match field {
                PortField::Src => "src_port",
                PortField::Dst => "dst_port",
                PortField::Either => "port",
            };
            format!("{} == \"{}-{}\"", field_name, min, max)
        }
        ConditionNode::PacketLength { operator, value } => {
            let op = match operator {
                LengthOperator::GreaterThan => ">",
                LengthOperator::LessThan => "<",
                LengthOperator::Equal => "==",
            };
            format!("length {} {}", op, value)
        }
        ConditionNode::TcpFlags { flags, mode: _ } => {
            let flags_str: Vec<String> = flags.iter().map(|f| format!("{:?}", f).to_uppercase()).collect();
            format!("tcp_flags == \"{}\"", flags_str.join(","))
        }
        ConditionNode::PayloadKeyword { pattern, compiled: _ } => {
            format!("payload == \"{}\"", escape_string(pattern))
        }
        ConditionNode::RateLimit { window_secs, threshold, src_ip } => {
            let src_str = if *src_ip { "src" } else { "dst" };
            format!("rate({}, {}, {})", window_secs, threshold, src_str)
        }
        ConditionNode::DnsBlacklist { domains } => {
            let domain_strs: Vec<String> = domains.iter().map(|d| format!("\"{}\"", d)).collect();
            format!("dns_blacklist({})", domain_strs.join(", "))
        }
    }
}

fn format_operand(node: &ConditionNode, is_or: bool) -> String {
    match node {
        ConditionNode::And { children } => {
            if is_or && children.len() > 1 {
                format!("({})", node_to_expression(node))
            } else {
                node_to_expression(node)
            }
        }
        ConditionNode::Or { children } => {
            if !is_or && children.len() > 1 {
                format!("({})", node_to_expression(node))
            } else {
                node_to_expression(node)
            }
        }
        _ => node_to_expression(node),
    }
}

fn escape_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn validate_cidr(cidr: &str) -> bool {
    cidr.parse::<cidr::IpCidr>().is_ok()
}

pub fn parse_expression(expr: &str) -> Result<ConditionNode, ParseError> {
    let mut parser = ExpressionParser::new(expr);
    parser.parse()
}
