mod decoder;
mod diagnostics;
mod model;
mod sessionizer;
mod timeline;

use model::{CaptureOverview, Flow, FlowStats, PacketSummary};
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::Mutex;

const MAX_FILE_SIZE: u64 = 500 * 1024 * 1024; // 500 MB
const ALLOWED_EXTENSIONS: &[&str] = &["pcap", "pcapng", "cap"];

fn validate_pcap_path(path: &Path) -> Result<(), String> {
    let canonical = path
        .canonicalize()
        .map_err(|_| "File not found or inaccessible".to_string())?;

    if !canonical.is_file() {
        return Err("Path is not a regular file".into());
    }

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

fn resolve_hostnames(ips: &[String]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for ip in ips {
        // Try reverse DNS with a short timeout via socket addr lookup
        let addr = format!("{}:0", ip);
        if let Ok(mut addrs) = addr.to_socket_addrs() {
            if let Some(sock) = addrs.next() {
                // Use the system DNS resolver via std
                if let Ok(host) = dns_lookup::lookup_addr(&sock.ip()) {
                    // Only store if the hostname differs from the IP
                    if host != *ip {
                        map.insert(ip.clone(), host);
                    }
                }
            }
        }
    }
    map
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

    let packets = decoder::decode_pcap(&canonical).map_err(|e| e.to_string())?;
    let total_packets = packets.len();

    if packets.is_empty() {
        return Ok(CaptureOverview {
            filename,
            total_packets: 0,
            duration: 0.0,
            flows: vec![],
            findings: vec![],
            hostnames: HashMap::new(),
        });
    }

    let first_ts = packets.first().map(|p| p.timestamp).unwrap_or(0.0);
    let last_ts = packets.last().map(|p| p.timestamp).unwrap_or(0.0);
    let duration = last_ts - first_ts;

    // Collect unique IPs for reverse DNS
    let mut unique_ips: Vec<String> = packets
        .iter()
        .flat_map(|p| vec![p.src_ip.clone(), p.dst_ip.clone()])
        .collect();
    unique_ips.sort();
    unique_ips.dedup();

    let hostnames = resolve_hostnames(&unique_ips);

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

        let protocol = flow_packets
            .iter()
            .rev()
            .find(|p| !["TCP", "UDP"].contains(&p.protocol.as_str()))
            .map(|p| p.protocol.clone())
            .unwrap_or_else(|| key.transport.clone());

        let events = timeline::build_timeline(flow_packets);
        let findings = diagnostics::analyze(&flow_id, &events);
        all_findings.extend(findings.clone());

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

    flows.sort_by(|a, b| a.start_time.partial_cmp(&b.start_time).unwrap());

    Ok(CaptureOverview {
        filename,
        total_packets,
        duration,
        flows,
        findings: all_findings,
        hostnames,
    })
}

struct CaptureState {
    child: Option<std::process::Child>,
    output_path: Option<String>,
}

#[tauri::command]
fn start_capture(interface: String, state: tauri::State<'_, Mutex<CaptureState>>) -> Result<String, String> {
    let mut guard = state.lock().map_err(|e| e.to_string())?;
    if guard.child.is_some() {
        return Err("A capture is already running".into());
    }

    let tmp_dir = std::env::temp_dir();
    let output_path = tmp_dir
        .join(format!("cesium-capture-{}.pcapng", uuid::Uuid::new_v4()))
        .to_string_lossy()
        .to_string();

    let child = std::process::Command::new("tshark")
        .args(["-i", &interface, "-w", &output_path])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start tshark: {}", e))?;

    guard.child = Some(child);
    guard.output_path = Some(output_path.clone());

    Ok(output_path)
}

#[tauri::command]
fn stop_capture(state: tauri::State<'_, Mutex<CaptureState>>) -> Result<String, String> {
    let mut guard = state.lock().map_err(|e| e.to_string())?;
    if let Some(mut child) = guard.child.take() {
        // Send SIGTERM on Unix
        #[cfg(unix)]
        {
            unsafe {
                libc::kill(child.id() as i32, libc::SIGTERM);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = child.kill();
        }
        let _ = child.wait();
    }

    guard.output_path.take().ok_or_else(|| "No capture was running".into())
}

#[tauri::command]
fn list_interfaces() -> Result<Vec<String>, String> {
    let output = std::process::Command::new("tshark")
        .args(["-D"])
        .output()
        .map_err(|e| format!("Failed to run tshark: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let interfaces: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            // Format: "1. en0 (Wi-Fi)" — extract the name
            let parts: Vec<&str> = line.splitn(2, ". ").collect();
            if parts.len() == 2 {
                Some(parts[1].to_string())
            } else {
                None
            }
        })
        .collect();

    Ok(interfaces)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .manage(Mutex::new(CaptureState {
            child: None,
            output_path: None,
        }))
        .invoke_handler(tauri::generate_handler![
            open_pcap,
            start_capture,
            stop_capture,
            list_interfaces
        ])
        .run(tauri::generate_context!())
        .expect("error while running Cesium");
}
