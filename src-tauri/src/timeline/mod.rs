use crate::model::{Packet, TimelineEvent};
use std::collections::HashMap;

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
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                == Some("1");

            let txid = dns
                .get("dns_dns_id")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let query_name = dns
                .get("dns_dns_qry_name")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
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
            let flags = tcp
                .get("tcp_tcp_flags_tree")
                .and_then(|t| t.as_object());

            let syn = flags
                .and_then(|f| f.get("tcp_tcp_flags_syn"))
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                == Some("1");
            let ack = flags
                .and_then(|f| f.get("tcp_tcp_flags_ack"))
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                == Some("1");
            let rst = flags
                .and_then(|f| f.get("tcp_tcp_flags_reset"))
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                == Some("1");
            let fin = flags
                .and_then(|f| f.get("tcp_tcp_flags_fin"))
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                == Some("1");

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

            // Retransmission (TShark marks this in tcp.analysis)
            let is_retrans = tcp
                .get("tcp_tcp_analysis")
                .and_then(|a| a.get("tcp_tcp_analysis_retransmission"))
                .is_some()
                || tcp
                    .get("tcp_tcp_analysis")
                    .and_then(|a| a.get("tcp_tcp_analysis_fast_retransmission"))
                    .is_some();

            if is_retrans {
                let seq = tcp
                    .get("tcp_tcp_seq")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
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
        }

        // --- TLS events ---
        if let Some(tls) = layers.get("tls") {
            let content_type = tls
                .get("tls_tls_record_content_type")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let handshake_type = tls
                .get("tls_tls_handshake_type")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");

            match handshake_type {
                "1" => {
                    events.push(TimelineEvent {
                        kind: "tls_client_hello".into(),
                        label: "TLS ClientHello".into(),
                        timestamp: pkt.timestamp,
                        duration: None,
                        frame_numbers: vec![pkt.frame_number],
                        details: HashMap::new(),
                    });
                }
                "2" => {
                    events.push(TimelineEvent {
                        kind: "tls_server_hello".into(),
                        label: "TLS ServerHello".into(),
                        timestamp: pkt.timestamp,
                        duration: None,
                        frame_numbers: vec![pkt.frame_number],
                        details: HashMap::new(),
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
        if let Some(http) = layers.get("http") {
            let method = http
                .get("http_http_request_method")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str());
            let uri = http
                .get("http_http_request_uri")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str());
            let status = http
                .get("http_http_response_code")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str());

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
