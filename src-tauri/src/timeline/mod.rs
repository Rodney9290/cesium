use crate::model::{Packet, TimelineEvent};
use std::collections::HashMap;

/// Extract a string from a JSON value that may be a plain string or an array of strings.
fn ek_str<'a>(value: &'a serde_json::Value) -> Option<&'a str> {
    value
        .as_str()
        .or_else(|| value.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()))
}

/// Extract a string field from a JSON object.
fn ek_field_str<'a>(obj: &'a serde_json::Map<String, serde_json::Value>, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(ek_str)
}

/// Check if a flag is set — handles bool (TShark 4.x) or string "1" (TShark 3.x).
fn ek_flag(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::String(s) => s == "1" || s == "true",
        serde_json::Value::Array(a) => a.first().map(ek_flag).unwrap_or(false),
        _ => false,
    }
}

/// Build timeline events from an ordered list of packets in a single flow.
pub fn build_timeline(packets: &[&Packet]) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    // Track DNS transactions (query → response) by transaction ID
    let mut dns_queries: HashMap<String, (f64, u64)> = HashMap::new();

    // Track TCP handshake state
    let mut syn_time: Option<(f64, u64)> = None;
    let mut syn_ack_time: Option<(f64, u64)> = None;

    for pkt in packets {
        let layers = &pkt.layers;

        // --- DNS events ---
        if let Some(dns) = layers.get("dns") {
            let is_response = dns
                .get("dns_dns_flags_response")
                .map(ek_flag)
                .unwrap_or(false);

            let txid = dns
                .get("dns_dns_id")
                .and_then(ek_str)
                .unwrap_or("")
                .to_string();

            let query_name = dns
                .get("dns_dns_qry_name")
                .and_then(ek_str)
                .unwrap_or("unknown");

            if !is_response {
                dns_queries.insert(txid.clone(), (pkt.timestamp, pkt.frame_number));
                events.push(TimelineEvent {
                    kind: "dns_query".into(),
                    label: format!("DNS Query: {}", query_name),
                    timestamp: pkt.timestamp,
                    duration: None,
                    frame_numbers: vec![pkt.frame_number],
                    details: HashMap::from([("query".into(), query_name.to_string())]),
                });
            } else if let Some((query_ts, query_frame)) = dns_queries.remove(&txid) {
                let duration_ms = (pkt.timestamp - query_ts) * 1000.0;
                events.push(TimelineEvent {
                    kind: "dns_response".into(),
                    label: format!("DNS Response: {}", query_name),
                    timestamp: pkt.timestamp,
                    duration: Some(duration_ms),
                    frame_numbers: vec![query_frame, pkt.frame_number],
                    details: HashMap::from([
                        ("query".into(), query_name.to_string()),
                        ("duration".into(), format!("{:.2}ms", duration_ms)),
                    ]),
                });
            }
        }

        // --- TCP events ---
        if let Some(tcp) = layers.get("tcp") {
            // TShark 4.x puts flags directly on the tcp object
            // TShark 3.x may use tcp_tcp_flags_tree sub-object
            let flags_obj = tcp
                .get("tcp_tcp_flags_tree")
                .unwrap_or(tcp);

            let syn = flags_obj.get("tcp_tcp_flags_syn").map(ek_flag).unwrap_or(false);
            let ack = flags_obj.get("tcp_tcp_flags_ack").map(ek_flag).unwrap_or(false);
            let rst = flags_obj.get("tcp_tcp_flags_reset").map(ek_flag).unwrap_or(false);
            let fin = flags_obj.get("tcp_tcp_flags_fin").map(ek_flag).unwrap_or(false);

            // SYN (no ACK) = connection initiation
            if syn && !ack {
                syn_time = Some((pkt.timestamp, pkt.frame_number));
                events.push(TimelineEvent {
                    kind: "tcp_syn".into(),
                    label: "TCP SYN".into(),
                    timestamp: pkt.timestamp,
                    duration: None,
                    frame_numbers: vec![pkt.frame_number],
                    details: HashMap::new(),
                });
            }
            // SYN+ACK
            else if syn && ack {
                syn_ack_time = Some((pkt.timestamp, pkt.frame_number));
                let rtt = syn_time.map(|(t, _)| (pkt.timestamp - t) * 1000.0);
                let mut details = HashMap::new();
                if let Some(rtt_ms) = rtt {
                    details.insert("rtt_to_server".into(), format!("{:.2}ms", rtt_ms));
                }
                events.push(TimelineEvent {
                    kind: "tcp_syn_ack".into(),
                    label: "TCP SYN/ACK".into(),
                    timestamp: pkt.timestamp,
                    duration: rtt,
                    frame_numbers: vec![pkt.frame_number],
                    details,
                });
            }
            // ACK completing handshake (first ACK after SYN/ACK)
            else if ack && !syn && syn_ack_time.is_some() && syn_time.is_some() {
                let total_ms = syn_time
                    .map(|(t, _)| (pkt.timestamp - t) * 1000.0)
                    .unwrap_or(0.0);
                let syn_frame = syn_time.map(|(_, f)| f).unwrap_or(0);
                let sa_frame = syn_ack_time.map(|(_, f)| f).unwrap_or(0);

                events.push(TimelineEvent {
                    kind: "tcp_handshake".into(),
                    label: "TCP Handshake Complete".into(),
                    timestamp: pkt.timestamp,
                    duration: Some(total_ms),
                    frame_numbers: vec![syn_frame, sa_frame, pkt.frame_number],
                    details: HashMap::from([(
                        "handshake_time".into(),
                        format!("{:.2}ms", total_ms),
                    )]),
                });

                // Clear so we don't re-trigger
                syn_time = None;
                syn_ack_time = None;
            }

            // RST
            if rst {
                events.push(TimelineEvent {
                    kind: "reset".into(),
                    label: "TCP Reset".into(),
                    timestamp: pkt.timestamp,
                    duration: None,
                    frame_numbers: vec![pkt.frame_number],
                    details: HashMap::new(),
                });
            }

            // FIN
            if fin {
                events.push(TimelineEvent {
                    kind: "fin".into(),
                    label: "TCP FIN".into(),
                    timestamp: pkt.timestamp,
                    duration: None,
                    frame_numbers: vec![pkt.frame_number],
                    details: HashMap::new(),
                });
            }

            // TCP analysis flags from TShark
            let analysis = tcp.get("tcp_tcp_analysis");

            // Retransmission
            let is_retrans = analysis
                .and_then(|a| a.get("tcp_tcp_analysis_retransmission"))
                .is_some()
                || analysis
                    .and_then(|a| a.get("tcp_tcp_analysis_fast_retransmission"))
                    .is_some();

            if is_retrans {
                let seq = tcp
                    .get("tcp_tcp_seq")
                    .and_then(ek_str)
                    .unwrap_or("?");
                events.push(TimelineEvent {
                    kind: "retransmission".into(),
                    label: "TCP Retransmission".into(),
                    timestamp: pkt.timestamp,
                    duration: None,
                    frame_numbers: vec![pkt.frame_number],
                    details: HashMap::from([("seq".into(), seq.to_string())]),
                });
            }

            // Duplicate ACK
            let is_dup_ack = analysis
                .and_then(|a| a.get("tcp_tcp_analysis_duplicate_ack"))
                .is_some()
                || analysis
                    .and_then(|a| a.get("tcp_tcp_analysis_duplicate_ack_num"))
                    .is_some();

            if is_dup_ack {
                events.push(TimelineEvent {
                    kind: "duplicate_ack".into(),
                    label: "Duplicate ACK".into(),
                    timestamp: pkt.timestamp,
                    duration: None,
                    frame_numbers: vec![pkt.frame_number],
                    details: HashMap::new(),
                });
            }

            // Out-of-order
            let is_ooo = analysis
                .and_then(|a| a.get("tcp_tcp_analysis_out_of_order"))
                .is_some();

            if is_ooo {
                events.push(TimelineEvent {
                    kind: "out_of_order".into(),
                    label: "Out-of-Order Segment".into(),
                    timestamp: pkt.timestamp,
                    duration: None,
                    frame_numbers: vec![pkt.frame_number],
                    details: HashMap::new(),
                });
            }

            // Zero window
            let window_size = tcp
                .get("tcp_tcp_window_size_value")
                .and_then(ek_str)
                .and_then(|s| s.parse::<u64>().ok());

            if window_size == Some(0) && !syn && !rst && !fin {
                events.push(TimelineEvent {
                    kind: "zero_window".into(),
                    label: "Zero Window".into(),
                    timestamp: pkt.timestamp,
                    duration: None,
                    frame_numbers: vec![pkt.frame_number],
                    details: HashMap::new(),
                });
            }
        }

        // --- TLS events ---
        if let Some(tls) = layers.get("tls") {
            let content_type = tls
                .get("tls_tls_record_content_type")
                .and_then(ek_str)
                .unwrap_or("");

            let handshake_type = tls
                .get("tls_tls_handshake_type")
                .and_then(ek_str)
                .unwrap_or("");

            let tls_version = tls
                .get("tls_tls_handshake_version")
                .and_then(ek_str)
                .or_else(|| tls.get("tls_tls_record_version").and_then(ek_str))
                .unwrap_or("")
                .to_string();

            let tls_version_name = match tls_version.as_str() {
                "768" => "SSL 3.0",
                "769" => "TLS 1.0",
                "770" => "TLS 1.1",
                "771" => "TLS 1.2",
                "772" => "TLS 1.3",
                _ => "",
            };

            match handshake_type {
                "1" => {
                    let mut details = HashMap::new();
                    if !tls_version.is_empty() {
                        details.insert("tls_version".into(), tls_version.clone());
                    }
                    if !tls_version_name.is_empty() {
                        details.insert("tls_version_name".into(), tls_version_name.into());
                    }
                    events.push(TimelineEvent {
                        kind: "tls_client_hello".into(),
                        label: if tls_version_name.is_empty() {
                            "TLS ClientHello".into()
                        } else {
                            format!("TLS ClientHello ({})", tls_version_name)
                        },
                        timestamp: pkt.timestamp,
                        duration: None,
                        frame_numbers: vec![pkt.frame_number],
                        details,
                    });
                }
                "2" => {
                    let mut details = HashMap::new();
                    if !tls_version.is_empty() {
                        details.insert("tls_version".into(), tls_version.clone());
                    }
                    if !tls_version_name.is_empty() {
                        details.insert("tls_version_name".into(), tls_version_name.into());
                    }
                    events.push(TimelineEvent {
                        kind: "tls_server_hello".into(),
                        label: if tls_version_name.is_empty() {
                            "TLS ServerHello".into()
                        } else {
                            format!("TLS ServerHello ({})", tls_version_name)
                        },
                        timestamp: pkt.timestamp,
                        duration: None,
                        frame_numbers: vec![pkt.frame_number],
                        details,
                    });
                }
                _ => {
                    if content_type == "22" && !handshake_type.is_empty() {
                        events.push(TimelineEvent {
                            kind: "tls_handshake".into(),
                            label: format!("TLS Handshake (type {})", handshake_type),
                            timestamp: pkt.timestamp,
                            duration: None,
                            frame_numbers: vec![pkt.frame_number],
                            details: HashMap::new(),
                        });
                    }
                }
            }
        }

        // --- HTTP events ---
        if let Some(http) = layers.get("http").and_then(|h| h.as_object()) {
            let method = ek_field_str(http, "http_http_request_method");
            let uri = ek_field_str(http, "http_http_request_uri");
            let status = ek_field_str(http, "http_http_response_code");

            if let (Some(method), Some(uri)) = (method, uri) {
                events.push(TimelineEvent {
                    kind: "http_request".into(),
                    label: format!("HTTP {} {}", method, uri),
                    timestamp: pkt.timestamp,
                    duration: None,
                    frame_numbers: vec![pkt.frame_number],
                    details: HashMap::from([
                        ("method".into(), method.to_string()),
                        ("uri".into(), uri.to_string()),
                    ]),
                });
            } else if let Some(status) = status {
                events.push(TimelineEvent {
                    kind: "http_response".into(),
                    label: format!("HTTP {}", status),
                    timestamp: pkt.timestamp,
                    duration: None,
                    frame_numbers: vec![pkt.frame_number],
                    details: HashMap::from([("status".into(), status.to_string())]),
                });
            }
        }
    }

    events.sort_by(|a, b| a.timestamp.partial_cmp(&b.timestamp).unwrap());
    events
}
