use crate::model::Packet;
use std::collections::HashMap;

/// A 5-tuple flow key (normalized so that src < dst for bidirectionality).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub ip_a: String,
    pub port_a: u16,
    pub ip_b: String,
    pub port_b: u16,
    pub transport: String,
}

impl FlowKey {
    pub fn from_packet(pkt: &Packet) -> Option<Self> {
        let src_port = pkt.src_port?;
        let dst_port = pkt.dst_port?;

        let transport = if pkt.layers.get("tcp").is_some() {
            "TCP"
        } else if pkt.layers.get("udp").is_some() {
            "UDP"
        } else {
            return None;
        };

        // Normalize direction so the same flow maps to the same key
        let (ip_a, port_a, ip_b, port_b) = if (&pkt.src_ip, src_port) <= (&pkt.dst_ip, dst_port) {
            (pkt.src_ip.clone(), src_port, pkt.dst_ip.clone(), dst_port)
        } else {
            (pkt.dst_ip.clone(), dst_port, pkt.src_ip.clone(), src_port)
        };

        Some(FlowKey {
            ip_a,
            port_a,
            ip_b,
            port_b,
            transport: transport.to_string(),
        })
    }
}

/// Group packets into flows by 5-tuple.
pub fn sessionize(packets: &[Packet]) -> HashMap<FlowKey, Vec<&Packet>> {
    let mut flows: HashMap<FlowKey, Vec<&Packet>> = HashMap::new();

    for pkt in packets {
        if let Some(key) = FlowKey::from_packet(pkt) {
            flows.entry(key).or_default().push(pkt);
        }
    }

    flows
}
