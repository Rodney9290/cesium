use crate::model::{Evidence, Finding, TimelineEvent};

/// Run all diagnostic rules against a flow's events and return findings.
pub fn analyze(flow_id: &str, events: &[TimelineEvent]) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_slow_dns(flow_id, events, &mut findings);
    check_incomplete_handshake(flow_id, events, &mut findings);
    check_retransmissions(flow_id, events, &mut findings);
    check_high_latency(flow_id, events, &mut findings);
    check_resets(flow_id, events, &mut findings);
    check_duplicate_acks(flow_id, events, &mut findings);
    check_out_of_order(flow_id, events, &mut findings);
    check_zero_window(flow_id, events, &mut findings);
    check_tls_version(flow_id, events, &mut findings);

    findings
}

fn check_slow_dns(flow_id: &str, events: &[TimelineEvent], findings: &mut Vec<Finding>) {
    let threshold_ms = 100.0;

    for event in events {
        if event.kind == "dns_response" {
            if let Some(dur) = event.duration {
                if dur > threshold_ms {
                    findings.push(Finding {
                        id: uuid::Uuid::new_v4().to_string(),
                        title: "Slow DNS Resolution".into(),
                        severity: "warning".into(),
                        confidence: "high".into(),
                        explanation: format!(
                            "DNS resolution took {:.1}ms, which exceeds the {:.0}ms threshold. \
                             This adds delay before the connection can even begin.",
                            dur, threshold_ms
                        ),
                        evidence: vec![Evidence {
                            label: "DNS duration".into(),
                            value: format!("{:.1}ms", dur),
                            frame_numbers: event.frame_numbers.clone(),
                        }],
                        caveat: Some(
                            "DNS latency can vary by resolver, caching, and network path."
                                .into(),
                        ),
                        flow_id: flow_id.into(),
                    });
                }
            }
        }
    }
}

fn check_incomplete_handshake(
    flow_id: &str,
    events: &[TimelineEvent],
    findings: &mut Vec<Finding>,
) {
    let has_syn = events.iter().any(|e| e.kind == "tcp_syn");
    let has_complete = events.iter().any(|e| e.kind == "tcp_handshake");

    if has_syn && !has_complete {
        let syn_frames: Vec<u64> = events
            .iter()
            .filter(|e| e.kind == "tcp_syn")
            .flat_map(|e| e.frame_numbers.clone())
            .collect();

        findings.push(Finding {
            id: uuid::Uuid::new_v4().to_string(),
            title: "Incomplete TCP Handshake".into(),
            severity: "error".into(),
            confidence: "high".into(),
            explanation:
                "A SYN was sent but the three-way handshake never completed. \
                 The remote host may be unreachable, the port may be closed, \
                 or a firewall may be dropping the packets."
                    .into(),
            evidence: vec![Evidence {
                label: "SYN packet(s)".into(),
                value: format!("{} SYN(s) without completion", syn_frames.len()),
                frame_numbers: syn_frames,
            }],
            caveat: Some(
                "If the capture started mid-connection, the handshake may have \
                 occurred before the capture began."
                    .into(),
            ),
            flow_id: flow_id.into(),
        });
    }
}

fn check_retransmissions(
    flow_id: &str,
    events: &[TimelineEvent],
    findings: &mut Vec<Finding>,
) {
    let retrans: Vec<&TimelineEvent> = events
        .iter()
        .filter(|e| e.kind == "retransmission")
        .collect();

    if !retrans.is_empty() {
        let frames: Vec<u64> = retrans
            .iter()
            .flat_map(|e| e.frame_numbers.clone())
            .collect();

        let severity = if retrans.len() > 5 { "error" } else { "warning" };

        findings.push(Finding {
            id: uuid::Uuid::new_v4().to_string(),
            title: format!("TCP Retransmissions ({})", retrans.len()),
            severity: severity.into(),
            confidence: "medium".into(),
            explanation: format!(
                "{} retransmitted segment(s) detected. Retransmissions occur when \
                 the sender doesn't receive an acknowledgment within the expected \
                 timeout (RTO), indicating possible packet loss on the network path.",
                retrans.len()
            ),
            evidence: vec![Evidence {
                label: "Retransmitted frames".into(),
                value: format!("{} retransmissions", retrans.len()),
                frame_numbers: frames,
            }],
            caveat: Some(
                "Some retransmissions may be spurious (caused by delayed ACKs \
                 or capture-point artifacts rather than actual loss)."
                    .into(),
            ),
            flow_id: flow_id.into(),
        });
    }
}

fn check_high_latency(
    flow_id: &str,
    events: &[TimelineEvent],
    findings: &mut Vec<Finding>,
) {
    let threshold_ms = 200.0;

    for event in events {
        if event.kind == "tcp_handshake" {
            if let Some(dur) = event.duration {
                if dur > threshold_ms {
                    findings.push(Finding {
                        id: uuid::Uuid::new_v4().to_string(),
                        title: "High TCP Handshake Latency".into(),
                        severity: "warning".into(),
                        confidence: "high".into(),
                        explanation: format!(
                            "The TCP three-way handshake took {:.1}ms. \
                             This is an estimate of the round-trip time (RTT) to the server. \
                             Values above {:.0}ms often indicate distant servers or congested paths.",
                            dur, threshold_ms
                        ),
                        evidence: vec![Evidence {
                            label: "Handshake duration".into(),
                            value: format!("{:.1}ms", dur),
                            frame_numbers: event.frame_numbers.clone(),
                        }],
                        caveat: Some(
                            "RTT measured from the capture point. If capturing on the server \
                             side, this reflects client-side latency instead."
                                .into(),
                        ),
                        flow_id: flow_id.into(),
                    });
                }
            }
        }
    }
}

fn check_resets(flow_id: &str, events: &[TimelineEvent], findings: &mut Vec<Finding>) {
    let resets: Vec<&TimelineEvent> = events.iter().filter(|e| e.kind == "reset").collect();

    if !resets.is_empty() {
        let frames: Vec<u64> = resets
            .iter()
            .flat_map(|e| e.frame_numbers.clone())
            .collect();

        findings.push(Finding {
            id: uuid::Uuid::new_v4().to_string(),
            title: "TCP Reset".into(),
            severity: "warning".into(),
            confidence: "high".into(),
            explanation:
                "The connection was abruptly terminated with a RST flag. \
                 This can indicate the remote host refused the connection, \
                 an application crash, or a firewall/middlebox intervention."
                    .into(),
            evidence: vec![Evidence {
                label: "RST frames".into(),
                value: format!("{} reset(s)", resets.len()),
                frame_numbers: frames,
            }],
            caveat: Some(
                "Some applications intentionally use RST for fast connection teardown."
                    .into(),
            ),
            flow_id: flow_id.into(),
        });
    }
}

fn check_duplicate_acks(
    flow_id: &str,
    events: &[TimelineEvent],
    findings: &mut Vec<Finding>,
) {
    let dup_acks: Vec<&TimelineEvent> = events
        .iter()
        .filter(|e| e.kind == "duplicate_ack")
        .collect();

    if dup_acks.len() >= 3 {
        let frames: Vec<u64> = dup_acks
            .iter()
            .flat_map(|e| e.frame_numbers.clone())
            .collect();

        findings.push(Finding {
            id: uuid::Uuid::new_v4().to_string(),
            title: format!("Duplicate ACKs ({})", dup_acks.len()),
            severity: "warning".into(),
            confidence: "medium".into(),
            explanation: format!(
                "{} duplicate ACKs detected. Three or more duplicate ACKs typically \
                 trigger TCP fast retransmit, indicating the receiver detected a gap \
                 in the data stream (likely packet loss).",
                dup_acks.len()
            ),
            evidence: vec![Evidence {
                label: "Duplicate ACK frames".into(),
                value: format!("{} duplicate ACKs", dup_acks.len()),
                frame_numbers: frames,
            }],
            caveat: Some(
                "Duplicate ACKs can also be caused by packet reordering, which is \
                 benign and more common on some network paths."
                    .into(),
            ),
            flow_id: flow_id.into(),
        });
    }
}

fn check_out_of_order(
    flow_id: &str,
    events: &[TimelineEvent],
    findings: &mut Vec<Finding>,
) {
    let ooo: Vec<&TimelineEvent> = events
        .iter()
        .filter(|e| e.kind == "out_of_order")
        .collect();

    if !ooo.is_empty() {
        let frames: Vec<u64> = ooo
            .iter()
            .flat_map(|e| e.frame_numbers.clone())
            .collect();

        findings.push(Finding {
            id: uuid::Uuid::new_v4().to_string(),
            title: format!("Out-of-Order Segments ({})", ooo.len()),
            severity: "info".into(),
            confidence: "medium".into(),
            explanation: format!(
                "{} out-of-order TCP segment(s) detected. Packets arrived at the capture \
                 point in a different order than they were sent, which can indicate \
                 multi-path routing or network congestion.",
                ooo.len()
            ),
            evidence: vec![Evidence {
                label: "Out-of-order frames".into(),
                value: format!("{} segments", ooo.len()),
                frame_numbers: frames,
            }],
            caveat: Some(
                "Minor reordering is normal, especially on paths with multiple routes. \
                 It only impacts performance if it triggers duplicate ACKs or retransmissions."
                    .into(),
            ),
            flow_id: flow_id.into(),
        });
    }
}

fn check_zero_window(
    flow_id: &str,
    events: &[TimelineEvent],
    findings: &mut Vec<Finding>,
) {
    let zw: Vec<&TimelineEvent> = events
        .iter()
        .filter(|e| e.kind == "zero_window")
        .collect();

    if !zw.is_empty() {
        let frames: Vec<u64> = zw
            .iter()
            .flat_map(|e| e.frame_numbers.clone())
            .collect();

        findings.push(Finding {
            id: uuid::Uuid::new_v4().to_string(),
            title: format!("Zero Window ({})", zw.len()),
            severity: "warning".into(),
            confidence: "high".into(),
            explanation: format!(
                "{} zero-window advertisement(s) detected. The receiver's TCP buffer is \
                 full, forcing the sender to pause transmission. This indicates the \
                 receiving application is not reading data fast enough.",
                zw.len()
            ),
            evidence: vec![Evidence {
                label: "Zero-window frames".into(),
                value: format!("{} occurrences", zw.len()),
                frame_numbers: frames,
            }],
            caveat: Some(
                "Zero-window is a flow-control mechanism, not an error. Brief \
                 occurrences are normal under burst traffic."
                    .into(),
            ),
            flow_id: flow_id.into(),
        });
    }
}

fn check_tls_version(
    flow_id: &str,
    events: &[TimelineEvent],
    findings: &mut Vec<Finding>,
) {
    for event in events {
        if event.kind == "tls_client_hello" || event.kind == "tls_server_hello" {
            if let Some(version) = event.details.get("tls_version") {
                let is_deprecated = matches!(
                    version.as_str(),
                    "768" | "769" | "770" // SSL 3.0, TLS 1.0, TLS 1.1
                );
                if is_deprecated {
                    let version_name = match version.as_str() {
                        "768" => "SSL 3.0",
                        "769" => "TLS 1.0",
                        "770" => "TLS 1.1",
                        _ => "Unknown",
                    };
                    findings.push(Finding {
                        id: uuid::Uuid::new_v4().to_string(),
                        title: format!("Deprecated TLS Version ({})", version_name),
                        severity: "error".into(),
                        confidence: "high".into(),
                        explanation: format!(
                            "This connection uses {}, which is deprecated and has known \
                             security vulnerabilities. Modern connections should use TLS 1.2 \
                             or TLS 1.3.",
                            version_name
                        ),
                        evidence: vec![Evidence {
                            label: "TLS version".into(),
                            value: version_name.to_string(),
                            frame_numbers: event.frame_numbers.clone(),
                        }],
                        caveat: Some(
                            "The ClientHello may advertise a lower version for compatibility \
                             while still negotiating a higher version via extensions."
                                .into(),
                        ),
                        flow_id: flow_id.into(),
                    });
                }
            }
        }
    }
}
