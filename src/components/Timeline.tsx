import type { TimelineEvent } from "../types";

interface Props {
  events: TimelineEvent[];
}

function dotClass(kind: string): string {
  if (kind.startsWith("dns")) return "dns";
  if (kind.startsWith("tcp") || kind === "fin" || kind === "reset") return "tcp";
  if (kind.startsWith("tls")) return "tls";
  if (kind.startsWith("http")) return "http";
  if (kind === "retransmission") return "error";
  return "info";
}

function formatDuration(ms: number): { text: string; speed: string } {
  const text = ms < 1 ? `${(ms * 1000).toFixed(0)}us` : `${ms.toFixed(1)}ms`;
  if (ms < 10) return { text, speed: "fast" };
  if (ms < 100) return { text, speed: "normal" };
  if (ms < 500) return { text, speed: "slow" };
  return { text, speed: "very-slow" };
}

function kindLabel(kind: string): string {
  const map: Record<string, string> = {
    dns_query: "DNS",
    dns_response: "DNS",
    tcp_syn: "TCP",
    tcp_syn_ack: "TCP",
    tcp_ack: "TCP",
    tcp_handshake: "TCP",
    tls_client_hello: "TLS",
    tls_server_hello: "TLS",
    tls_handshake: "TLS",
    http_request: "HTTP",
    http_response: "HTTP",
    retransmission: "!",
    reset: "R",
    fin: "F",
  };
  return map[kind] ?? "?";
}

export function Timeline({ events }: Props) {
  if (events.length === 0) {
    return (
      <p style={{ color: "var(--text-tertiary)" }}>
        No events detected for this connection.
      </p>
    );
  }

  return (
    <div>
      {events.map((event, i) => {
        const dur = event.duration ? formatDuration(event.duration) : null;
        return (
          <div className="timeline-event" key={i}>
            <div className={`timeline-dot ${dotClass(event.kind)}`}>
              {kindLabel(event.kind)}
            </div>
            <div className="timeline-content">
              <div className="timeline-label">
                {event.label}
                {dur && (
                  <span className={`timing-pill ${dur.speed}`}>
                    {dur.text}
                  </span>
                )}
              </div>
              {Object.entries(event.details).map(([k, v]) => (
                <div className="timeline-detail" key={k}>
                  {k}: {v}
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
