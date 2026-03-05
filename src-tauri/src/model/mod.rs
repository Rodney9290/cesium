use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub frame_number: u64,
    pub timestamp: f64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub length: u64,
    pub info: String,
    /// Raw TShark layer data for deeper inspection
    pub layers: serde_json::Value,
}

/// Compact packet summary sent to the frontend for the detail panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSummary {
    #[serde(rename = "frameNumber")]
    pub frame_number: u64,
    pub timestamp: f64,
    #[serde(rename = "relativeTime")]
    pub relative_time: f64,
    #[serde(rename = "deltaTime")]
    pub delta_time: f64,
    #[serde(rename = "srcIp")]
    pub src_ip: String,
    #[serde(rename = "dstIp")]
    pub dst_ip: String,
    #[serde(rename = "srcPort")]
    pub src_port: Option<u16>,
    #[serde(rename = "dstPort")]
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub length: u64,
    pub info: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStats {
    #[serde(rename = "throughputBps")]
    pub throughput_bps: f64,
    #[serde(rename = "avgPacketSize")]
    pub avg_packet_size: f64,
    #[serde(rename = "rttMs")]
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub id: String,
    #[serde(rename = "srcIp")]
    pub src_ip: String,
    #[serde(rename = "srcPort")]
    pub src_port: u16,
    #[serde(rename = "dstIp")]
    pub dst_ip: String,
    #[serde(rename = "dstPort")]
    pub dst_port: u16,
    pub protocol: String,
    #[serde(rename = "packetCount")]
    pub packet_count: usize,
    pub bytes: u64,
    #[serde(rename = "startTime")]
    pub start_time: f64,
    #[serde(rename = "endTime")]
    pub end_time: f64,
    pub events: Vec<TimelineEvent>,
    pub findings: Vec<Finding>,
    pub stats: FlowStats,
    pub packets: Vec<PacketSummary>,
    #[serde(rename = "anomalyScore")]
    pub anomaly_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub kind: String,
    pub label: String,
    pub timestamp: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<f64>,
    #[serde(rename = "frameNumbers")]
    pub frame_numbers: Vec<u64>,
    pub details: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub explanation: String,
    pub evidence: Vec<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caveat: Option<String>,
    #[serde(rename = "flowId")]
    pub flow_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub label: String,
    pub value: String,
    #[serde(rename = "frameNumbers")]
    pub frame_numbers: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureOverview {
    pub filename: String,
    #[serde(rename = "totalPackets")]
    pub total_packets: usize,
    pub duration: f64,
    pub flows: Vec<Flow>,
    pub findings: Vec<Finding>,
    pub hostnames: std::collections::HashMap<String, String>,
}
