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

/// Check that tshark is available and return its version string.
pub fn check_tshark() -> Result<String, DecoderError> {
    let output = Command::new("tshark")
        .arg("--version")
        .output()
        .map_err(|_| DecoderError::TsharkNotFound)?;

    if !output.status.success() {
        return Err(DecoderError::TsharkNotFound);
    }

    let version = String::from_utf8_lossy(&output.stdout);
    let first_line = version.lines().next().unwrap_or("unknown");
    Ok(first_line.to_string())
}

/// Decode a PCAP file into a Vec<Packet> using tshark JSON output.
///
/// Uses `--no-duplicate-keys` to avoid JSON parsing issues with
/// duplicate field names in some protocol dissections.
pub fn decode_pcap(path: &Path) -> Result<Vec<Packet>, DecoderError> {
    let child = Command::new("tshark")
        .args([
            "-r",
            path.to_str().unwrap_or(""),
            "-T",
            "ek",
            "--no-duplicate-keys",
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
            .and_then(|f| f.get("frame_frame_number"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let timestamp = frame
            .and_then(|f| f.get("frame_frame_time_epoch"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);

        let length = frame
            .and_then(|f| f.get("frame_frame_len"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let protocol = frame
            .and_then(|f| f.get("frame_frame_protocols"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .map(|s| {
                // Take the highest-level protocol from the colon-separated list
                s.split(':').last().unwrap_or(s).to_uppercase()
            })
            .unwrap_or_else(|| "UNKNOWN".into());

        let ip = layers.get("ip").and_then(|i| i.as_object());
        let src_ip = ip
            .and_then(|i| i.get("ip_ip_src"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0")
            .to_string();
        let dst_ip = ip
            .and_then(|i| i.get("ip_ip_dst"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0")
            .to_string();

        let tcp = layers.get("tcp").and_then(|t| t.as_object());
        let udp = layers.get("udp").and_then(|u| u.as_object());

        let (src_port, dst_port) = if let Some(tcp) = tcp {
            (
                tcp.get("tcp_tcp_srcport")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u16>().ok()),
                tcp.get("tcp_tcp_dstport")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u16>().ok()),
            )
        } else if let Some(udp) = udp {
            (
                udp.get("udp_udp_srcport")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u16>().ok()),
                udp.get("udp_udp_dstport")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
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
