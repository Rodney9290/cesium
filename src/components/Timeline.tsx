import { useState, useMemo } from "react";
import type { TimelineEvent } from "../types";

interface Props {
  events: TimelineEvent[];
}

function dotClass(kind: string): string {
  if (kind.startsWith("dns")) return "dns";
  if (kind.startsWith("tcp") || kind === "fin" || kind === "reset") return "tcp";
  if (kind.startsWith("tls")) return "tls";
  if (kind.startsWith("http")) return "http";
  if (kind === "retransmission" || kind === "duplicate_ack" || kind === "out_of_order")
    return "error";
  if (kind === "zero_window") return "warning-dot";
  return "info";
}

function formatDuration(ms: number): { text: string; speed: string } {
  const text = ms < 1 ? `${(ms * 1000).toFixed(0)}µs` : `${ms.toFixed(1)}ms`;
  if (ms < 10) return { text, speed: "fast" };
  if (ms < 100) return { text, speed: "normal" };
  if (ms < 500) return { text, speed: "slow" };
  return { text, speed: "very-slow" };
}

function kindLabel(kind: string): string {
  const map: Record<string, string> = {
    dns_query: "DNS",
    dns_response: "DNS",
    tcp_syn: "SYN",
    tcp_syn_ack: "S/A",
    tcp_ack: "ACK",
    tcp_handshake: "TCP",
    tls_client_hello: "TLS",
    tls_server_hello: "TLS",
    tls_handshake: "TLS",
    http_request: "HTTP",
    http_response: "HTTP",
    retransmission: "!",
    duplicate_ack: "DA",
    out_of_order: "OO",
    zero_window: "ZW",
    reset: "R",
    fin: "F",
  };
  return map[kind] ?? "?";
}

type FilterKind = "all" | "dns" | "tcp" | "tls" | "http" | "issues";

export function Timeline({ events }: Props) {
  const [filter, setFilter] = useState<FilterKind>("all");
  const [collapsed, setCollapsed] = useState(false);

  const filtered = useMemo(() => {
    if (filter === "all") return events;
    if (filter === "issues")
      return events.filter(
        (e) =>
          e.kind === "retransmission" ||
          e.kind === "duplicate_ack" ||
          e.kind === "out_of_order" ||
          e.kind === "zero_window" ||
          e.kind === "reset",
      );
    return events.filter((e) => {
      if (filter === "dns") return e.kind.startsWith("dns");
      if (filter === "tcp")
        return (
          e.kind.startsWith("tcp") || e.kind === "fin" || e.kind === "reset"
        );
      if (filter === "tls") return e.kind.startsWith("tls");
      if (filter === "http") return e.kind.startsWith("http");
      return true;
    });
  }, [events, filter]);

  if (events.length === 0) {
    return (
      <p style={{ color: "var(--text-tertiary)" }}>
        No events detected for this connection.
      </p>
    );
  }

  return (
    <div className="timeline-container">
      <div className="timeline-toolbar">
        <div className="timeline-filters">
          {(["all", "dns", "tcp", "tls", "http", "issues"] as FilterKind[]).map(
            (f) => (
              <button
                key={f}
                className={`timeline-filter-btn ${filter === f ? "active" : ""}`}
                onClick={() => setFilter(f)}
              >
                {f === "all"
                  ? `All (${events.length})`
                  : f.toUpperCase()}
              </button>
            ),
          )}
        </div>
        {filtered.length > 20 && (
          <button
            className="timeline-filter-btn"
            onClick={() => setCollapsed(!collapsed)}
          >
            {collapsed ? "Expand All" : "Collapse"}
          </button>
        )}
      </div>
      <div className="timeline-scroll">
        {(collapsed ? filtered.slice(0, 20) : filtered).map((event, i) => {
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
                {Object.entries(event.details)
                  .filter(([k]) => !k.startsWith("tls_version"))
                  .map(([k, v]) => (
                    <div className="timeline-detail" key={k}>
                      {k}: {v}
                    </div>
                  ))}
              </div>
            </div>
          );
        })}
        {collapsed && filtered.length > 20 && (
          <div
            className="timeline-more"
            onClick={() => setCollapsed(false)}
          >
            +{filtered.length - 20} more events — click to expand
          </div>
        )}
      </div>
    </div>
  );
}
