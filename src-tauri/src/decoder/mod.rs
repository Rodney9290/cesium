use crate::model::Packet;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const TSHARK_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_PACKETS: usize = 500_000;

#[derive(Debug, thiserror::Error)]
pub enum DecoderError {
    #[error("TShark not found. Please install Wireshark/TShark and ensure it is on your PATH.")]
    TsharkNotFound,
    #[error("TShark failed: {0}")]
    TsharkFailed(String),
    #[error("Failed to parse TShark output: {0}")]
    ParseError(String),
    #[error("Packet limit exceeded ({0} packets). Try a smaller capture.")]
    TooManyPackets(usize),
    #[error("TShark timed out after {} seconds", TSHARK_TIMEOUT.as_secs())]
    Timeout,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Extract a string from a JSON value that may be either a plain string or an array of strings.
/// TShark 3.x uses arrays, TShark 4.x uses plain values.
fn ek_str<'a>(value: &'a serde_json::Value) -> Option<&'a str> {
    value
        .as_str()
        .or_else(|| value.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()))
}

/// Extract a string field from a JSON object, handling both array and plain formats.
fn ek_field_str<'a>(obj: &'a serde_json::Map<String, serde_json::Value>, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(ek_str)
}

/// Parse a timestamp that may be either a Unix epoch float or an ISO 8601 string.
fn parse_timestamp(s: &str) -> Option<f64> {
    // Try as float first (TShark 3.x)
    if let Ok(ts) = s.parse::<f64>() {
        // Sanity check: valid epoch timestamps are > 1e9 (year 2001+)
        if ts > 1e9 {
            return Some(ts);
        }
    }
    // Try as ISO 8601 (TShark 4.x): "2026-03-05T15:31:57.327271000Z"
    if s.contains('T') && s.contains('-') {
        // Parse manually: extract seconds since epoch
        // Format: YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ
        let ts_str = s.trim_end_matches('Z');
        let (date_time, nanos_str) = ts_str.split_once('.').unwrap_or((ts_str, "0"));
        let nanos: f64 = format!("0.{}", nanos_str).parse().unwrap_or(0.0);

        // Use a simple approach: parse with chrono-like manual calculation
        let parts: Vec<&str> = date_time.split('T').collect();
        if parts.len() == 2 {
            let date_parts: Vec<u32> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
            let time_parts: Vec<&str> = parts[1].split(':').collect();
            if date_parts.len() == 3 && time_parts.len() == 3 {
                let year = date_parts[0] as i64;
                let month = date_parts[1];
                let day = date_parts[2];
                let hour: u32 = time_parts[0].parse().unwrap_or(0);
                let minute: u32 = time_parts[1].parse().unwrap_or(0);
                let second: u32 = time_parts[2].parse().unwrap_or(0);

                // Days from epoch (1970-01-01) using a simplified calculation
                let mut days: i64 = 0;
                for y in 1970..year {
                    days += if is_leap(y) { 366 } else { 365 };
                }
                let month_days = [0, 31, 28 + if is_leap(year) { 1 } else { 0 },
                    31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
                for m in 1..month {
                    days += month_days[m as usize] as i64;
                }
                days += (day as i64) - 1;

                let epoch = days * 86400
                    + (hour as i64) * 3600
                    + (minute as i64) * 60
                    + (second as i64);
                return Some(epoch as f64 + nanos);
            }
        }
    }
    None
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Decode a PCAP file into a Vec<Packet> using tshark EK (newline-delimited JSON) output.
pub fn decode_pcap(path: &Path) -> Result<Vec<Packet>, DecoderError> {
    let child = Command::new("tshark")
        .args([
            "-r",
            path.to_str().unwrap_or(""),
            "-T",
            "ek",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|_| DecoderError::TsharkNotFound)?;

    // Wait with timeout via a thread
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let result = child.wait_with_output();
        let _ = tx.send(result);
    });

    let output = match rx.recv_timeout(TSHARK_TIMEOUT) {
        Ok(Ok(output)) => {
            if !output.status.success() {
                let err = String::from_utf8_lossy(&output.stderr);
                return Err(DecoderError::TsharkFailed(err.to_string()));
            }
            output.stdout
        }
        Ok(Err(e)) => return Err(DecoderError::Io(e)),
        Err(_) => {
            drop(handle);
            return Err(DecoderError::Timeout);
        }
    };

    let stdout = String::from_utf8_lossy(&output);
    let mut packets = Vec::new();

    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }

        if packets.len() >= MAX_PACKETS {
            return Err(DecoderError::TooManyPackets(MAX_PACKETS));
        }

        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| DecoderError::ParseError(e.to_string()))?;

        // TShark -T ek produces "index" lines and data lines.
        // We only care about data lines (those with "layers").
        let Some(layers) = value.get("layers") else {
            continue;
        };

        let frame = layers.get("frame").and_then(|f| f.as_object());

        let frame_number = frame
            .and_then(|f| ek_field_str(f, "frame_frame_number"))
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let timestamp = frame
            .and_then(|f| ek_field_str(f, "frame_frame_time_epoch"))
            .and_then(parse_timestamp)
            .unwrap_or(0.0);

        let length = frame
            .and_then(|f| ek_field_str(f, "frame_frame_len"))
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let protocol = frame
            .and_then(|f| ek_field_str(f, "frame_frame_protocols"))
            .map(|s| {
                // Take the highest-level protocol from the colon-separated list
                s.split(':').last().unwrap_or(s).to_uppercase()
            })
            .unwrap_or_else(|| "UNKNOWN".into());

        let ip = layers.get("ip").and_then(|i| i.as_object());
        let src_ip = ip
            .and_then(|i| ek_field_str(i, "ip_ip_src"))
            .unwrap_or("0.0.0.0")
            .to_string();
        let dst_ip = ip
            .and_then(|i| ek_field_str(i, "ip_ip_dst"))
            .unwrap_or("0.0.0.0")
            .to_string();

        let tcp = layers.get("tcp").and_then(|t| t.as_object());
        let udp = layers.get("udp").and_then(|u| u.as_object());

        let (src_port, dst_port) = if let Some(tcp) = tcp {
            (
                ek_field_str(tcp, "tcp_tcp_srcport")
                    .and_then(|s| s.parse::<u16>().ok()),
                ek_field_str(tcp, "tcp_tcp_dstport")
                    .and_then(|s| s.parse::<u16>().ok()),
            )
        } else if let Some(udp) = udp {
            (
                ek_field_str(udp, "udp_udp_srcport")
                    .and_then(|s| s.parse::<u16>().ok()),
                ek_field_str(udp, "udp_udp_dstport")
                    .and_then(|s| s.parse::<u16>().ok()),
            )
        } else {
            (None, None)
        };

        // Build a short info string
        let info = format!(
            "{} {} → {}",
            protocol,
            src_port.map(|p| p.to_string()).unwrap_or_default(),
            dst_port.map(|p| p.to_string()).unwrap_or_default(),
        );

        packets.push(Packet {
            frame_number,
            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            length,
            info,
            layers: layers.clone(),
        });
    }

    Ok(packets)
}
