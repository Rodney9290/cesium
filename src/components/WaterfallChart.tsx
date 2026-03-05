import { useMemo } from "react";
import type { Flow } from "../types";

interface Props {
  flows: Flow[];
  hostnames: Record<string, string>;
  selectedFlowId: string | null;
  onSelectFlow: (id: string) => void;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

const PROTOCOL_COLORS: Record<string, string> = {
  TLS: "#ff9500",
  TCP: "#34c759",
  DNS: "#5856d6",
  HTTP: "#007aff",
  QUIC: "#af52de",
  UDP: "#86868b",
  MDNS: "#5856d6",
};

export function WaterfallChart({ flows, hostnames, selectedFlowId, onSelectFlow }: Props) {
  const { minTime, maxTime, totalHeight } = useMemo(() => {
    if (flows.length === 0) return { minTime: 0, maxTime: 1, barHeight: 24, totalHeight: 0 };
    const min = Math.min(...flows.map((f) => f.startTime));
    const max = Math.max(...flows.map((f) => f.endTime));
    const bh = 24;
    return { minTime: min, maxTime: max || min + 1, barHeight: bh, totalHeight: flows.length * (bh + 4) };
  }, [flows]);

  const range = maxTime - minTime || 1;

  if (flows.length === 0) {
    return <p style={{ color: "var(--text-tertiary)" }}>No flows to display.</p>;
  }

  return (
    <div className="waterfall-chart">
      <div className="waterfall-header">
        <span className="waterfall-col-label">Connection</span>
        <span className="waterfall-col-timeline">Timeline</span>
        <span className="waterfall-col-size">Size</span>
      </div>
      <div className="waterfall-body" style={{ height: Math.min(totalHeight, 600) }}>
        {flows.map((flow) => {
          const left = ((flow.startTime - minTime) / range) * 100;
          const width = Math.max(((flow.endTime - flow.startTime) / range) * 100, 0.5);
          const color = PROTOCOL_COLORS[flow.protocol] || "#86868b";
          const label = hostnames[flow.dstIp] || flow.dstIp;

          return (
            <div
              key={flow.id}
              className={`waterfall-row ${flow.id === selectedFlowId ? "selected" : ""}`}
              onClick={() => onSelectFlow(flow.id)}
            >
              <span className="waterfall-label" title={`${flow.srcIp} → ${flow.dstIp}`}>
                <span className={`proto-badge ${flow.protocol.toLowerCase()}`}>
                  {flow.protocol}
                </span>
                {label}
              </span>
              <span className="waterfall-bar-container">
                <span
                  className="waterfall-bar"
                  style={{ left: `${left}%`, width: `${width}%`, background: color }}
                  title={`${((flow.endTime - flow.startTime) * 1000).toFixed(1)}ms`}
                />
              </span>
              <span className="waterfall-size">{formatBytes(flow.bytes)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
