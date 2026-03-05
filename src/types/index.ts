export interface PacketSummary {
  frameNumber: number;
  timestamp: number;
  relativeTime: number;
  deltaTime: number;
  srcIp: string;
  dstIp: string;
  srcPort: number | null;
  dstPort: number | null;
  protocol: string;
  length: number;
  info: string;
}

export interface FlowStats {
  throughputBps: number;
  avgPacketSize: number;
  rttMs: number | null;
}

export interface Flow {
  id: string;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: string;
  packetCount: number;
  bytes: number;
  startTime: number;
  endTime: number;
  events: TimelineEvent[];
  findings: Finding[];
  stats: FlowStats;
  packets: PacketSummary[];
  anomalyScore: number;
}

export type EventKind =
  | "dns_query"
  | "dns_response"
  | "tcp_syn"
  | "tcp_syn_ack"
  | "tcp_ack"
  | "tcp_handshake"
  | "tls_client_hello"
  | "tls_server_hello"
  | "tls_handshake"
  | "http_request"
  | "http_response"
  | "retransmission"
  | "duplicate_ack"
  | "out_of_order"
  | "zero_window"
  | "reset"
  | "fin"
  | "unknown";

export interface TimelineEvent {
  kind: EventKind;
  label: string;
  timestamp: number;
  duration?: number;
  frameNumbers: number[];
  details: Record<string, string>;
}

export type Severity = "info" | "warning" | "error";
export type Confidence = "high" | "medium" | "low";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  explanation: string;
  evidence: Evidence[];
  caveat?: string;
  flowId: string;
}

export interface Evidence {
  label: string;
  value: string;
  frameNumbers: number[];
}

export interface CaptureOverview {
  filename: string;
  totalPackets: number;
  duration: number;
  flows: Flow[];
  findings: Finding[];
  hostnames: Record<string, string>;
}
