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
        let addr = format!("{}:0", ip);
        if let Ok(mut addrs) = addr.to_socket_addrs() {
            if let Some(sock) = addrs.next() {
                if let Ok(host) = dns_lookup::lookup_addr(&sock.ip()) {
                    if host != *ip {
                        map.insert(ip.clone(), host);
                    }
                }
            }
        }
    }
    map
}

fn compute_anomaly_score(flow: &Flow) -> f64 {
    let mut score: f64 = 0.0;

    // Error findings contribute heavily
    for f in &flow.findings {
        match f.severity.as_str() {
            "error" => score += 30.0,
            "warning" => score += 15.0,
            _ => score += 5.0,
        }
    }

    // Retransmissions
    let retrans = flow.events.iter().filter(|e| e.kind == "retransmission").count();
    score += retrans as f64 * 10.0;

    // Duplicate ACKs
    let dup_acks = flow.events.iter().filter(|e| e.kind == "duplicate_ack").count();
    score += dup_acks as f64 * 5.0;

    // Resets
    let resets = flow.events.iter().filter(|e| e.kind == "reset").count();
    score += resets as f64 * 20.0;

    // Zero windows
    let zero_win = flow.events.iter().filter(|e| e.kind == "zero_window").count();
    score += zero_win as f64 * 15.0;

    // Out of order
    let ooo = flow.events.iter().filter(|e| e.kind == "out_of_order").count();
    score += ooo as f64 * 8.0;

    // High RTT
    if let Some(rtt) = flow.stats.rtt_ms {
        if rtt > 200.0 { score += 20.0; }
        else if rtt > 100.0 { score += 10.0; }
        else if rtt > 50.0 { score += 5.0; }
    }

    // Normalize to 0-100
    score.min(100.0)
}

struct AppState {
    capture_child: Option<std::process::Child>,
    capture_output_path: Option<String>,
    last_pcap_path: Option<String>,
}

#[tauri::command]
fn open_pcap(path: String, state: tauri::State<'_, Mutex<AppState>>) -> Result<CaptureOverview, String> {
    let file_path = Path::new(&path);

    validate_pcap_path(file_path)?;

    let canonical = file_path.canonicalize().map_err(|e| e.to_string())?;

    // Store path for later hex/detail queries
    if let Ok(mut guard) = state.lock() {
        guard.last_pcap_path = Some(canonical.to_string_lossy().to_string());
    }

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

        let mut flow = Flow {
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
            anomaly_score: 0.0,
        };
        flow.anomaly_score = compute_anomaly_score(&flow);
        flows.push(flow);
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

#[tauri::command]
fn get_packet_hex(frame_number: u64, state: tauri::State<'_, Mutex<AppState>>) -> Result<String, String> {
    let pcap_path = state.lock()
        .map_err(|e| e.to_string())?
        .last_pcap_path.clone()
        .ok_or_else(|| "No capture loaded".to_string())?;

    let output = std::process::Command::new("tshark")
        .args([
            "-r", &pcap_path,
            "-Y", &format!("frame.number == {}", frame_number),
            "-x",
        ])
        .output()
        .map_err(|e| format!("Failed to run tshark: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[tauri::command]
fn get_packet_details(frame_number: u64, state: tauri::State<'_, Mutex<AppState>>) -> Result<String, String> {
    let pcap_path = state.lock()
        .map_err(|e| e.to_string())?
        .last_pcap_path.clone()
        .ok_or_else(|| "No capture loaded".to_string())?;

    let output = std::process::Command::new("tshark")
        .args([
            "-r", &pcap_path,
            "-Y", &format!("frame.number == {}", frame_number),
            "-V",
        ])
        .output()
        .map_err(|e| format!("Failed to run tshark: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[tauri::command]
fn follow_tcp_stream(flow_index: u32, state: tauri::State<'_, Mutex<AppState>>) -> Result<String, String> {
    let pcap_path = state.lock()
        .map_err(|e| e.to_string())?
        .last_pcap_path.clone()
        .ok_or_else(|| "No capture loaded".to_string())?;

    let output = std::process::Command::new("tshark")
        .args([
            "-r", &pcap_path,
            "-z", &format!("follow,tcp,ascii,{}", flow_index),
            "-q",
        ])
        .output()
        .map_err(|e| format!("Failed to run tshark: {}", e))?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[tauri::command]
fn get_tls_info(state: tauri::State<'_, Mutex<AppState>>) -> Result<String, String> {
    let pcap_path = state.lock()
        .map_err(|e| e.to_string())?
        .last_pcap_path.clone()
        .ok_or_else(|| "No capture loaded".to_string())?;

    let output = std::process::Command::new("tshark")
        .args([
            "-r", &pcap_path,
            "-Y", "tls.handshake.type == 11",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "x509ce.dNSName",
            "-e", "x509af.utcTime",
            "-e", "x509sat.uTF8String",
            "-e", "tls.handshake.ciphersuite",
            "-e", "tls.record.version",
            "-E", "header=y",
            "-E", "separator=|",
        ])
        .output()
        .map_err(|e| format!("Failed to run tshark: {}", e))?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[tauri::command]
fn get_dns_timeline(state: tauri::State<'_, Mutex<AppState>>) -> Result<String, String> {
    let pcap_path = state.lock()
        .map_err(|e| e.to_string())?
        .last_pcap_path.clone()
        .ok_or_else(|| "No capture loaded".to_string())?;

    let output = std::process::Command::new("tshark")
        .args([
            "-r", &pcap_path,
            "-Y", "dns",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_relative",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "dns.qry.name",
            "-e", "dns.qry.type",
            "-e", "dns.flags.response",
            "-e", "dns.a",
            "-e", "dns.aaaa",
            "-e", "dns.cname",
            "-e", "dns.flags.rcode",
            "-e", "dns.time",
            "-E", "header=y",
            "-E", "separator=|",
        ])
        .output()
        .map_err(|e| format!("Failed to run tshark: {}", e))?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[tauri::command]
fn get_http_payloads(state: tauri::State<'_, Mutex<AppState>>) -> Result<String, String> {
    let pcap_path = state.lock()
        .map_err(|e| e.to_string())?
        .last_pcap_path.clone()
        .ok_or_else(|| "No capture loaded".to_string())?;

    let output = std::process::Command::new("tshark")
        .args([
            "-r", &pcap_path,
            "-Y", "http",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_relative",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "http.request.method",
            "-e", "http.request.uri",
            "-e", "http.response.code",
            "-e", "http.content_type",
            "-e", "http.content_length",
            "-e", "http.host",
            "-e", "http.user_agent",
            "-e", "http.server",
            "-E", "header=y",
            "-E", "separator=|",
        ])
        .output()
        .map_err(|e| format!("Failed to run tshark: {}", e))?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[tauri::command]
fn get_stream_data(src_ip: String, src_port: u16, dst_ip: String, dst_port: u16, state: tauri::State<'_, Mutex<AppState>>) -> Result<String, String> {
    let pcap_path = state.lock()
        .map_err(|e| e.to_string())?
        .last_pcap_path.clone()
        .ok_or_else(|| "No capture loaded".to_string())?;

    // First find the TCP stream index for this flow
    let filter = format!(
        "(ip.addr == {} && ip.addr == {} && tcp.port == {} && tcp.port == {})",
        src_ip, dst_ip, src_port, dst_port
    );

    let output = std::process::Command::new("tshark")
        .args([
            "-r", &pcap_path,
            "-Y", &filter,
            "-T", "fields",
            "-e", "tcp.stream",
            "-c", "1",
        ])
        .output()
        .map_err(|e| format!("Failed to run tshark: {}", e))?;

    let stream_index = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stream_index.is_empty() {
        return Err("Could not find TCP stream for this flow".to_string());
    }

    // Now follow that stream
    let follow_output = std::process::Command::new("tshark")
        .args([
            "-r", &pcap_path,
            "-z", &format!("follow,tcp,ascii,{}", stream_index),
            "-q",
        ])
        .output()
        .map_err(|e| format!("Failed to run tshark: {}", e))?;

    Ok(String::from_utf8_lossy(&follow_output.stdout).to_string())
}

#[tauri::command]
fn start_capture(interface: String, state: tauri::State<'_, Mutex<AppState>>) -> Result<String, String> {
    let mut guard = state.lock().map_err(|e| e.to_string())?;
    if guard.capture_child.is_some() {
        return Err("A capture is already running".into());
    }

    let tmp_dir = std::env::temp_dir();
    let output_path = tmp_dir
        .join(format!("cesium-capture-{}.pcapng", uuid::Uuid::new_v4()))
        .to_string_lossy()
        .to_string();

    let (program, args) = if which_exists("dumpcap") {
        ("dumpcap", vec!["-i".to_string(), interface.clone(), "-w".to_string(), output_path.clone()])
    } else {
        ("tshark", vec!["-i".to_string(), interface.clone(), "-w".to_string(), output_path.clone()])
    };

    let mut child = std::process::Command::new(program)
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start {}: {}", program, e))?;

    std::thread::sleep(std::time::Duration::from_millis(500));

    match child.try_wait() {
        Ok(Some(status)) => {
            let stderr = child.stderr.take()
                .and_then(|mut s| {
                    let mut buf = String::new();
                    std::io::Read::read_to_string(&mut s, &mut buf).ok()?;
                    Some(buf)
                })
                .unwrap_or_default();
            let msg = if stderr.trim().is_empty() {
                format!("{} exited with {}", program, status)
            } else {
                stderr.trim().to_string()
            };
            if msg.contains("permission") || msg.contains("Permission") || status.code() == Some(2) {
                return Err(format!(
                    "Capture failed: {}. On macOS, try: sudo chmod +x /usr/local/bin/dumpcap, or run Cesium with elevated permissions.",
                    msg
                ));
            }
            return Err(format!("Capture failed: {}", msg));
        }
        Ok(None) => {}
        Err(e) => return Err(format!("Failed to check capture status: {}", e)),
    }

    guard.capture_child = Some(child);
    guard.capture_output_path = Some(output_path.clone());

    Ok(output_path)
}

fn which_exists(name: &str) -> bool {
    std::process::Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tauri::command]
fn stop_capture(state: tauri::State<'_, Mutex<AppState>>) -> Result<String, String> {
    let mut guard = state.lock().map_err(|e| e.to_string())?;
    let output_path = guard.capture_output_path.take()
        .ok_or_else(|| "No capture was running".to_string())?;

    if let Some(mut child) = guard.capture_child.take() {
        #[cfg(unix)]
        {
            unsafe {
                libc::kill(child.id() as i32, libc::SIGINT);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = child.kill();
        }
        let _ = child.wait();
    }

    let path = std::path::Path::new(&output_path);
    if !path.exists() {
        return Err("Capture file was not created. The capture tool may have lacked permissions. On macOS, try running with sudo.".into());
    }

    Ok(output_path)
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
        .manage(Mutex::new(AppState {
            capture_child: None,
            capture_output_path: None,
            last_pcap_path: None,
        }))
        .invoke_handler(tauri::generate_handler![
            open_pcap,
            start_capture,
            stop_capture,
            list_interfaces,
            get_packet_hex,
            get_packet_details,
            follow_tcp_stream,
            get_tls_info,
            get_dns_timeline,
            get_http_payloads,
            get_stream_data
        ])
        .run(tauri::generate_context!())
        .expect("error while running Cesium");
}
