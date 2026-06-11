use cidr::IpCidr;
use super::models::*;

#[derive(Debug, Clone)]
enum ConditionSet {
    Any,
    Never,
    Protocols(Vec<String>),
    IpRanges {
        field: IpField,
        cidrs: Vec<IpCidr>,
    },
    PortRanges {
        field: PortField,
        ranges: Vec<(u16, u16)>,
    },
    PacketLengthGt(u32),
    PacketLengthLt(u32),
    PacketLengthEq(u32),
    TcpFlagsSet {
        flags: Vec<TcpFlag>,
        mode: FlagMatchMode,
    },
    PayloadPattern(String),
    RateLimitCond {
        window_secs: u32,
        threshold: u32,
        src_ip: bool,
    },
    DnsBlacklistSet(Vec<String>),
    And(Vec<ConditionSet>),
    Or(Vec<ConditionSet>),
    Not(Box<ConditionSet>),
}

fn to_condition_set(node: &ConditionNode) -> ConditionSet {
    match node {
        ConditionNode::And { children } => {
            ConditionSet::And(children.iter().map(to_condition_set).collect())
        }
        ConditionNode::Or { children } => {
            ConditionSet::Or(children.iter().map(to_condition_set).collect())
        }
        ConditionNode::Not { child } => {
            ConditionSet::Not(Box::new(to_condition_set(child)))
        }
        ConditionNode::ProtocolMatch { protocol } => {
            ConditionSet::Protocols(vec![protocol.to_lowercase()])
        }
        ConditionNode::IpMatch { field, cidr } => {
            match cidr.parse::<IpCidr>() {
                Ok(c) => ConditionSet::IpRanges {
                    field: *field,
                    cidrs: vec![c],
                },
                Err(_) => ConditionSet::Any,
            }
        }
        ConditionNode::PortRange { field, min, max } => {
            ConditionSet::PortRanges {
                field: *field,
                ranges: vec![(*min, *max)],
            }
        }
        ConditionNode::PacketLength { operator, value } => {
            match operator {
                LengthOperator::GreaterThan => ConditionSet::PacketLengthGt(*value),
                LengthOperator::LessThan => ConditionSet::PacketLengthLt(*value),
                LengthOperator::Equal => ConditionSet::PacketLengthEq(*value),
            }
        }
        ConditionNode::TcpFlags { flags, mode } => {
            ConditionSet::TcpFlagsSet {
                flags: flags.clone(),
                mode: *mode,
            }
        }
        ConditionNode::PayloadKeyword { pattern, .. } => {
            ConditionSet::PayloadPattern(pattern.clone())
        }
        ConditionNode::RateLimit { window_secs, threshold, src_ip } => {
            ConditionSet::RateLimitCond {
                window_secs: *window_secs,
                threshold: *threshold,
                src_ip: *src_ip,
            }
        }
        ConditionNode::DnsBlacklist { domains } => {
            ConditionSet::DnsBlacklistSet(domains.clone())
        }
    }
}

fn cidr_intersection(cidrs_a: &[IpCidr], cidrs_b: &[IpCidr]) -> bool {
    if cidrs_a.is_empty() || cidrs_b.is_empty() {
        return true;
    }
    for a in cidrs_a {
        for b in cidrs_b {
            if cidrs_overlap(a, b) {
                return true;
            }
        }
    }
    false
}

fn cidrs_overlap(a: &IpCidr, b: &IpCidr) -> bool {
    let a_min = network_addr(a);
    let a_max = broadcast_addr(a);
    let b_min = network_addr(b);
    let b_max = broadcast_addr(b);
    a_min <= b_max && b_min <= a_max
}

fn network_addr(cidr: &IpCidr) -> u128 {
    match cidr {
        IpCidr::V4(c) => {
            u32::from(c.first_address()) as u128
        }
        IpCidr::V6(c) => {
            u128::from(c.first_address())
        }
    }
}

fn broadcast_addr(cidr: &IpCidr) -> u128 {
    match cidr {
        IpCidr::V4(c) => {
            u32::from(c.last_address()) as u128
        }
        IpCidr::V6(c) => {
            u128::from(c.last_address())
        }
    }
}

fn port_ranges_intersect(ranges_a: &[(u16, u16)], ranges_b: &[(u16, u16)]) -> bool {
    if ranges_a.is_empty() || ranges_b.is_empty() {
        return true;
    }
    for (min_a, max_a) in ranges_a {
        for (min_b, max_b) in ranges_b {
            if min_a <= max_b && min_b <= max_a {
                return true;
            }
        }
    }
    false
}

fn ip_fields_compatible(a: IpField, b: IpField) -> bool {
    match (a, b) {
        (IpField::Src, IpField::Src) => true,
        (IpField::Dst, IpField::Dst) => true,
        (IpField::Either, _) | (_, IpField::Either) => true,
        _ => false,
    }
}

fn port_fields_compatible(a: PortField, b: PortField) -> bool {
    match (a, b) {
        (PortField::Src, PortField::Src) => true,
        (PortField::Dst, PortField::Dst) => true,
        (PortField::Either, _) | (_, PortField::Either) => true,
        _ => false,
    }
}

fn conditions_have_intersection(a: &ConditionSet, b: &ConditionSet) -> bool {
    match (a, b) {
        (ConditionSet::Any, _) | (_, ConditionSet::Any) => true,
        (ConditionSet::Never, _) | (_, ConditionSet::Never) => false,

        (ConditionSet::Protocols(pa), ConditionSet::Protocols(pb)) => {
            pa.iter().any(|p| pb.iter().any(|q| p == q))
        }

        (ConditionSet::IpRanges { field: fa, cidrs: ca }, ConditionSet::IpRanges { field: fb, cidrs: cb }) => {
            ip_fields_compatible(*fa, *fb) && cidr_intersection(ca, cb)
        }

        (ConditionSet::PortRanges { field: fa, ranges: ra }, ConditionSet::PortRanges { field: fb, ranges: rb }) => {
            port_fields_compatible(*fa, *fb) && port_ranges_intersect(ra, rb)
        }

        (ConditionSet::PacketLengthGt(va), ConditionSet::PacketLengthGt(_)) => true,
        (ConditionSet::PacketLengthLt(va), ConditionSet::PacketLengthLt(_)) => true,
        (ConditionSet::PacketLengthGt(va), ConditionSet::PacketLengthLt(vb)) => *va < *vb,
        (ConditionSet::PacketLengthLt(va), ConditionSet::PacketLengthGt(vb)) => *vb < *va,
        (ConditionSet::PacketLengthEq(va), ConditionSet::PacketLengthGt(vb)) => *va > *vb,
        (ConditionSet::PacketLengthEq(va), ConditionSet::PacketLengthLt(vb)) => *va < *vb,
        (ConditionSet::PacketLengthGt(va), ConditionSet::PacketLengthEq(vb)) => *vb > *va,
        (ConditionSet::PacketLengthLt(va), ConditionSet::PacketLengthEq(vb)) => *vb < *va,
        (ConditionSet::PacketLengthEq(va), ConditionSet::PacketLengthEq(vb)) => va == vb,

        (ConditionSet::TcpFlagsSet { .. }, ConditionSet::TcpFlagsSet { .. }) => true,

        (ConditionSet::PayloadPattern(_), ConditionSet::PayloadPattern(_)) => true,

        (ConditionSet::RateLimitCond { .. }, ConditionSet::RateLimitCond { .. }) => true,

        (ConditionSet::DnsBlacklistSet(da), ConditionSet::DnsBlacklistSet(db)) => {
            da.iter().any(|d| db.iter().any(|e| d == e))
        }

        (ConditionSet::And(children_a), ConditionSet::And(children_b)) => {
            children_a.iter().all(|ca| {
                children_b.iter().any(|cb| conditions_have_intersection(ca, cb))
            }) || children_b.iter().all(|cb| {
                children_a.iter().any(|ca| conditions_have_intersection(ca, cb))
            })
        }

        (ConditionSet::And(children), other) | (other, ConditionSet::And(children)) => {
            children.iter().all(|c| conditions_have_intersection(c, other))
        }

        (ConditionSet::Or(children_a), ConditionSet::Or(children_b)) => {
            children_a.iter().any(|ca| {
                children_b.iter().any(|cb| conditions_have_intersection(ca, cb))
            })
        }

        (ConditionSet::Or(children), other) | (other, ConditionSet::Or(children)) => {
            children.iter().any(|c| conditions_have_intersection(c, other))
        }

        (ConditionSet::Not(inner_a), ConditionSet::Not(inner_b)) => {
            not_and_not_intersect(inner_a, inner_b)
        }

        (ConditionSet::Not(inner), other) | (other, ConditionSet::Not(inner)) => {
            let (not_inner, other_set) = if matches!(a, ConditionSet::Not(_)) {
                (inner.as_ref(), b)
            } else {
                (inner.as_ref(), a)
            };
            not_and_other_intersect(not_inner, other_set)
        }

        _ => true,
    }
}

fn not_and_other_intersect(not_inner: &ConditionSet, other: &ConditionSet) -> bool {
    match (not_inner, other) {
        (ConditionSet::Any, _) => false,
        (_, ConditionSet::Never) | (ConditionSet::Never, _) => false,
        (_, ConditionSet::Any) => true,

        (ConditionSet::Protocols(not_protos), ConditionSet::Protocols(other_protos)) => {
            other_protos.iter().any(|p| !not_protos.contains(p))
        }

        (ConditionSet::IpRanges { field: nf, cidrs: nc }, ConditionSet::IpRanges { field: of, cidrs: oc }) => {
            if !ip_fields_compatible(*nf, *of) {
                return true;
            }
            !cidrs_subset_of(oc, nc)
        }

        (ConditionSet::PortRanges { field: nf, ranges: nr }, ConditionSet::PortRanges { field: of, ranges: or }) => {
            if !port_fields_compatible(*nf, *of) {
                return true;
            }
            !port_ranges_subset_of(or, nr)
        }

        (ConditionSet::PacketLengthGt(nv), ConditionSet::PacketLengthGt(ov)) => {
            *ov <= *nv
        }
        (ConditionSet::PacketLengthGt(nv), ConditionSet::PacketLengthLt(ov)) => {
            *ov > 0
        }
        (ConditionSet::PacketLengthGt(nv), ConditionSet::PacketLengthEq(ov)) => {
            *ov <= *nv
        }
        (ConditionSet::PacketLengthLt(nv), ConditionSet::PacketLengthGt(ov)) => {
            true
        }
        (ConditionSet::PacketLengthLt(nv), ConditionSet::PacketLengthLt(ov)) => {
            *ov > 0
        }
        (ConditionSet::PacketLengthLt(nv), ConditionSet::PacketLengthEq(ov)) => {
            *ov < *nv
        }
        (ConditionSet::PacketLengthEq(nv), ConditionSet::PacketLengthGt(ov)) => {
            *nv <= *ov
        }
        (ConditionSet::PacketLengthEq(nv), ConditionSet::PacketLengthLt(ov)) => {
            *nv >= *ov
        }
        (ConditionSet::PacketLengthEq(nv), ConditionSet::PacketLengthEq(ov)) => {
            *nv != *ov
        }

        (ConditionSet::And(children), _) => {
            !children.iter().all(|c| not_and_other_intersect(c, other) == false)
        }
        (_, ConditionSet::And(children)) => {
            children.iter().all(|c| not_and_other_intersect(not_inner, c))
        }

        (ConditionSet::Or(children), _) => {
            children.iter().all(|c| not_and_other_intersect(c, other))
        }
        (_, ConditionSet::Or(children)) => {
            children.iter().any(|c| not_and_other_intersect(not_inner, c))
        }

        (ConditionSet::Not(inner), _) => {
            conditions_have_intersection(inner, other)
        }

        _ => true,
    }
}

fn not_and_not_intersect(a: &ConditionSet, b: &ConditionSet) -> bool {
    !conditions_are_exhaustive(a, b)
}

fn conditions_are_exhaustive(a: &ConditionSet, b: &ConditionSet) -> bool {
    match (a, b) {
        (ConditionSet::Protocols(pa), ConditionSet::Protocols(pb)) => {
            let common_set: std::collections::HashSet<String> = pa.iter().chain(pb.iter()).cloned().collect();
            common_set.len() >= 200
        }
        _ => false,
    }
}

fn cidrs_subset_of(subject: &[IpCidr], superset: &[IpCidr]) -> bool {
    if superset.is_empty() {
        return subject.is_empty();
    }
    for s in subject {
        let s_min = network_addr(s);
        let s_max = broadcast_addr(s);
        let mut covered = false;
        for super_c in superset {
            let super_min = network_addr(super_c);
            let super_max = broadcast_addr(super_c);
            if super_min <= s_min && s_max <= super_max {
                covered = true;
                break;
            }
        }
        if !covered {
            return false;
        }
    }
    true
}

fn port_ranges_subset_of(subject: &[(u16, u16)], superset: &[(u16, u16)]) -> bool {
    if superset.is_empty() {
        return subject.is_empty();
    }
    for (s_min, s_max) in subject {
        let mut covered = false;
        for (super_min, super_max) in superset {
            if super_min <= s_min && s_max <= super_max {
                covered = true;
                break;
            }
        }
        if !covered {
            return false;
        }
    }
    true
}

fn actions_conflict(a: &AlertActions, b: &AlertActions) -> Option<String> {
    if a.auto_mark && b.auto_mark {
        if a.mark_level != b.mark_level {
            let level_a = a.mark_level.as_deref().unwrap_or("none");
            let level_b = b.mark_level.as_deref().unwrap_or("none");
            return Some(format!("标记级别冲突: 规则A标记为\"{}\", 规则B标记为\"{}\"", level_a, level_b));
        }
    }

    if a.system_notification && b.system_notification {
        // Both notify, no conflict
    }

    if a.auto_mark && !b.auto_mark && b.system_notification {
        // One marks, one just notifies - different response levels
    }

    None
}

fn describe_intersection(a: &DetectionRule, b: &DetectionRule) -> String {
    let set_a = to_condition_set(&a.condition);
    let set_b = to_condition_set(&b.condition);
    let mut parts = Vec::new();

    describe_intersection_recursive(&set_a, &set_b, &mut parts);

    if parts.is_empty() {
        "条件存在交集".to_string()
    } else {
        parts.join("; ")
    }
}

fn describe_intersection_recursive(a: &ConditionSet, b: &ConditionSet, parts: &mut Vec<String>) {
    match (a, b) {
        (ConditionSet::Protocols(pa), ConditionSet::Protocols(pb)) => {
            let common: Vec<&String> = pa.iter().filter(|p| pb.contains(p)).collect();
            if !common.is_empty() {
                let s: Vec<&str> = common.iter().map(|s| s.as_str()).collect();
                parts.push(format!("共同协议: {}", s.join(",")));
            }
        }
        (ConditionSet::IpRanges { field, cidrs }, ConditionSet::IpRanges { field: fb, cidrs: cb }) => {
            if ip_fields_compatible(*field, *fb) {
                let field_name = match field {
                    IpField::Src => "源IP",
                    IpField::Dst => "目的IP",
                    IpField::Either => "IP",
                };
                parts.push(format!("{}范围存在交集", field_name));
            }
        }
        (ConditionSet::PortRanges { field, ranges: ra }, ConditionSet::PortRanges { field: fb, ranges: rb }) => {
            if port_fields_compatible(*field, *fb) {
                let field_name = match field {
                    PortField::Src => "源端口",
                    PortField::Dst => "目的端口",
                    PortField::Either => "端口",
                };
                if port_ranges_intersect(ra, rb) {
                    parts.push(format!("{}范围存在交集", field_name));
                }
            }
        }
        (ConditionSet::And(children_a), ConditionSet::And(children_b)) => {
            for ca in children_a {
                for cb in children_b {
                    describe_intersection_recursive(ca, cb, parts);
                }
            }
        }
        (ConditionSet::And(children), other) | (other, ConditionSet::And(children)) => {
            for c in children {
                describe_intersection_recursive(c, other, parts);
            }
        }
        (ConditionSet::Or(children_a), ConditionSet::Or(children_b)) => {
            for ca in children_a {
                for cb in children_b {
                    describe_intersection_recursive(ca, cb, parts);
                }
            }
        }
        (ConditionSet::Or(children), other) | (other, ConditionSet::Or(children)) => {
            for c in children {
                describe_intersection_recursive(c, other, parts);
            }
        }
        _ => {}
    }
}

pub fn check_conflict(existing: &DetectionRule, new_rule: &DetectionRule) -> Option<RuleConflict> {
    let set_a = to_condition_set(&existing.condition);
    let set_b = to_condition_set(&new_rule.condition);

    if !conditions_have_intersection(&set_a, &set_b) {
        return None;
    }

    let action_conflict = actions_conflict(&existing.actions, &new_rule.actions);
    if action_conflict.is_none() {
        return None;
    }

    Some(RuleConflict {
        rule_a_id: existing.id.clone(),
        rule_a_name: existing.name.clone(),
        rule_b_id: new_rule.id.clone(),
        rule_b_name: new_rule.name.clone(),
        intersection_desc: describe_intersection(existing, new_rule),
        action_conflict: action_conflict.unwrap(),
    })
}
