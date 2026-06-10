use crate::models::NetworkInterface;
use pcap::Device;

pub fn list_interfaces() -> Vec<NetworkInterface> {
    let devices = Device::list().unwrap_or_default();
    devices.into_iter().map(|d| {
        let ips: Vec<String> = d.addresses.iter().map(|a| {
            format!("{}", a.addr)
        }).collect();
        let mac = d.addresses.iter()
            .filter_map(|a| a.netmask)
            .map(|a| format!("{}", a))
            .next();
        NetworkInterface {
            name: d.name.clone(),
            friendly_name: d.desc.unwrap_or(d.name),
            ips,
            mac,
            is_up: d.flags.is_up(),
            is_loopback: d.flags.is_loopback(),
        }
    }).collect()
}
