mod decoder;
mod diagnostics;
mod model;
mod sessionizer;
mod timeline;

use model::{CaptureOverview, Flow, FlowStats, PacketSummary};
use std::path::Path;

const MAX_FILE_SIZE: u64 = 500 * 1024 * 1024; // 500 MB
const ALLOWED_EXTENSIONS: &[&str] = &["pcap", "pcapng", "cap"];

fn validate_pcap_path(path: &Path) -> Result<(), String> {
    // Canonicalize to prevent path traversal
    let canonical = path
        .canonicalize()
        .map_err(|_| "File not found or inaccessible".to_string())?;

    // Must be a file, not a directory or symlink to something unexpected
    if !canonical.is_file() {
        return Err("Path is not a regular file".into());
    }

    // Validate extension
    let ext = canonical
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();
    if !ALLOWED_EXTENSIONS.contains(&ext.as_str()) {
        return Err(format!(
            "Unsupported file type '.{}'. Expected: .pcap, .pcapng, or .cap",
            ext
        ));
    }

    // Enforce file size limit
    let metadata = std::fs::metadata(&canonical)
        .map_err(|_| "Cannot read file metadata".to_string())?;
    if metadata.len() > MAX_FILE_SIZE {
        return Err(format!(
            "File too large ({:.0} MB). Maximum supported size is {:.0} MB",
            metadata.len() as f64 / (1024.0 * 1024.0),
            MAX_FILE_SIZE as f64 / (1024.0 * 1024.0)
        ));
    }

    Ok(())
}

#[tauri::command]
fn open_pcap(path: String) -> Result<CaptureOverview, String> {
    let file_path = Path::new(&path);

    validate_pcap_path(file_path)?;

    let canonical = file_path.canonicalize().map_err(|e| e.to_string())?;

    let filename = canonical
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.clone());

    // Decode packets via TShark
    let packets = decoder::decode_pcap(&canonical).map_err(|e| e.to_string())?;
    let total_packets = packets.len();

    if packets.is_empty() {
        return Ok(CaptureOverview {
            filename,
            total_packets: 0,
            duration: 0.0,
            flows: vec![],
            findings: vec![],
        });
    }

    let first_ts = packets.first().map(|p| p.timestamp).unwrap_or(0.0);
    let last_ts = packets.last().map(|p| p.timestamp).unwrap_or(0.0);
    let duration = last_ts - first_ts;

    // Sessionize into flows
    let flow_map = sessionizer::sessionize(&packets);

    let mut flows: Vec<Flow> = Vec::new();
    let mut all_findings = Vec::new();

    for (key, flow_packets) in &flow_map {
        let flow_id = uuid::Uuid::new_v4().to_string();
        let bytes: u64 = flow_packets.iter().map(|p| p.length).sum();
        let start_time = flow_packets
            .first()
            .map(|p| p.timestamp)
            .unwrap_or(0.0);
        let end_time = flow_packets
            .last()
            .map(|p| p.timestamp)
            .unwrap_or(0.0);

        // Determine the "most interesting" protocol in the flow
        let protocol = flow_packets
            .iter()
            .rev()
            .find(|p| !["TCP", "UDP"].contains(&p.protocol.as_str()))
            .map(|p| p.protocol.clone())
            .unwrap_or_else(|| key.transport.clone());

        // Build timeline
        let events = timeline::build_timeline(flow_packets);

        // Run diagnostics
        let findings = diagnostics::analyze(&flow_id, &events);
        all_findings.extend(findings.clone());

        // Compute stats
        let flow_duration = end_time - start_time;
        let throughput_bps = if flow_duration > 0.0 {
            (bytes as f64 * 8.0) / flow_duration
        } else {
            0.0
        };
        let avg_packet_size = if !flow_packets.is_empty() {
            bytes as f64 / flow_packets.len() as f64
        } else {
            0.0
        };
        let rtt_ms = events.iter().find_map(|e| {
            if e.kind == "tcp_syn_ack" {
                e.duration
            } else {
                None
            }
        });

        // Build packet summaries for detail panel
        let packet_summaries: Vec<PacketSummary> = flow_packets
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let delta = if i > 0 {
                    p.timestamp - flow_packets[i - 1].timestamp
                } else {
                    0.0
                };
                PacketSummary {
                    frame_number: p.frame_number,
                    timestamp: p.timestamp,
                    relative_time: p.timestamp - start_time,
                    delta_time: delta,
                    src_ip: p.src_ip.clone(),
                    dst_ip: p.dst_ip.clone(),
                    src_port: p.src_port,
                    dst_port: p.dst_port,
                    protocol: p.protocol.clone(),
                    length: p.length,
                    info: p.info.clone(),
                }
            })
            .collect();

        flows.push(Flow {
            id: flow_id,
            src_ip: key.ip_a.clone(),
            src_port: key.port_a,
            dst_ip: key.ip_b.clone(),
            dst_port: key.port_b,
            protocol,
            packet_count: flow_packets.len(),
            bytes,
            start_time,
            end_time,
            events,
            findings,
            stats: FlowStats {
                throughput_bps,
                avg_packet_size,
                rtt_ms,
            },
            packets: packet_summaries,
        });
    }

    // Sort flows by start time
    flows.sort_by(|a, b| a.start_time.partial_cmp(&b.start_time).unwrap());

    Ok(CaptureOverview {
        filename,
        total_packets,
        duration,
        flows,
        findings: all_findings,
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![open_pcap])
        .run(tauri::generate_context!())
        .expect("error while running Cesium");
}
