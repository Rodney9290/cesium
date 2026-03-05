use crate::model::{Evidence, Finding, TimelineEvent};

/// Run all diagnostic rules against a flow's events and return findings.
pub fn analyze(flow_id: &str, events: &[TimelineEvent]) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_slow_dns(flow_id, events, &mut findings);
    check_incomplete_handshake(flow_id, events, &mut findings);
    check_retransmissions(flow_id, events, &mut findings);
    check_high_latency(flow_id, events, &mut findings);
    check_resets(flow_id, events, &mut findings);

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
