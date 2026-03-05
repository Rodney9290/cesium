import { useMemo } from "react";
import type { Flow } from "../types";

interface Props {
  flows: Flow[];
  onSelectFlow: (id: string) => void;
}

// Simple IP-to-region heuristic based on IP ranges (no external DB needed)
// This maps common private/reserved ranges and uses geographic hints from hostnames
function classifyIp(ip: string): { label: string; x: number; y: number } | null {
  if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.")) {
    return { label: "Private Network", x: 50, y: 50 };
  }
  if (ip.startsWith("127.")) return null;
  if (ip === "::1" || ip === "0.0.0.0") return null;

  // Use IP first octet as a rough geographic hint
  const first = parseInt(ip.split(".")[0] || "0");
  if (first >= 1 && first <= 63) return { label: "North America", x: 22, y: 38 };
  if (first >= 64 && first <= 95) return { label: "North America", x: 25, y: 42 };
  if (first >= 96 && first <= 126) return { label: "North America", x: 20, y: 35 };
  if (first >= 128 && first <= 159) return { label: "Europe", x: 52, y: 32 };
  if (first >= 160 && first <= 175) return { label: "Europe", x: 48, y: 35 };
  if (first >= 176 && first <= 191) return { label: "Europe", x: 55, y: 30 };
  if (first >= 192 && first <= 207) return { label: "Asia-Pacific", x: 78, y: 40 };
  if (first >= 208 && first <= 223) return { label: "Americas", x: 28, y: 55 };
  return { label: "Unknown", x: 50, y: 50 };
}

interface GeoNode {
  region: string;
  x: number;
  y: number;
  ips: Set<string>;
  totalBytes: number;
  flowCount: number;
}

export function GeoIpMap({ flows, onSelectFlow }: Props) {
  const { nodes, connections } = useMemo(() => {
    const regionMap = new Map<string, GeoNode>();

    for (const flow of flows) {
      for (const ip of [flow.srcIp, flow.dstIp]) {
        const geo = classifyIp(ip);
        if (!geo) continue;
        const existing = regionMap.get(geo.label);
        if (existing) {
          existing.ips.add(ip);
          existing.totalBytes += flow.bytes;
          existing.flowCount++;
        } else {
          regionMap.set(geo.label, {
            region: geo.label,
            x: geo.x,
            y: geo.y,
            ips: new Set([ip]),
            totalBytes: flow.bytes,
            flowCount: 1,
          });
        }
      }
    }

    const nodes = Array.from(regionMap.values());
    const maxBytes = Math.max(...nodes.map((n) => n.totalBytes), 1);

    const connections: { from: GeoNode; to: GeoNode; flow: Flow }[] = [];
    for (const flow of flows) {
      const srcGeo = classifyIp(flow.srcIp);
      const dstGeo = classifyIp(flow.dstIp);
      if (srcGeo && dstGeo && srcGeo.label !== dstGeo.label) {
        const from = regionMap.get(srcGeo.label);
        const to = regionMap.get(dstGeo.label);
        if (from && to) connections.push({ from, to, flow });
      }
    }

    return { nodes, connections, maxBytes };
  }, [flows]);

  return (
    <div className="geo-map">
      <svg viewBox="0 0 100 65" className="geo-map-svg">
        {/* Simple world outline */}
        <rect x="0" y="0" width="100" height="65" fill="var(--bg-tertiary)" rx="4" />

        {/* Continent outlines (simplified) */}
        <ellipse cx="22" cy="38" rx="12" ry="10" fill="none" stroke="var(--border)" strokeWidth="0.3" opacity="0.5" />
        <ellipse cx="52" cy="32" rx="10" ry="8" fill="none" stroke="var(--border)" strokeWidth="0.3" opacity="0.5" />
        <ellipse cx="68" cy="55" rx="6" ry="5" fill="none" stroke="var(--border)" strokeWidth="0.3" opacity="0.5" />
        <ellipse cx="78" cy="38" rx="12" ry="10" fill="none" stroke="var(--border)" strokeWidth="0.3" opacity="0.5" />
        <ellipse cx="25" cy="55" rx="8" ry="6" fill="none" stroke="var(--border)" strokeWidth="0.3" opacity="0.5" />

        {/* Connection lines */}
        {connections.slice(0, 50).map((conn, i) => (
          <line
            key={i}
            x1={conn.from.x}
            y1={conn.from.y}
            x2={conn.to.x}
            y2={conn.to.y}
            stroke="var(--accent)"
            strokeWidth="0.2"
            opacity="0.3"
            onClick={() => onSelectFlow(conn.flow.id)}
            style={{ cursor: "pointer" }}
          />
        ))}

        {/* Region nodes */}
        {nodes.map((node) => {
          const radius = Math.max(1.5, Math.min(4, (node.flowCount / flows.length) * 8));
          return (
            <g key={node.region}>
              <circle
                cx={node.x}
                cy={node.y}
                r={radius}
                fill="var(--accent)"
                opacity="0.7"
              />
              <circle
                cx={node.x}
                cy={node.y}
                r={radius + 1}
                fill="none"
                stroke="var(--accent)"
                strokeWidth="0.2"
                opacity="0.3"
              />
              <text
                x={node.x}
                y={node.y - radius - 1.5}
                textAnchor="middle"
                fontSize="2.2"
                fill="var(--text-secondary)"
              >
                {node.region}
              </text>
              <text
                x={node.x}
                y={node.y + radius + 3}
                textAnchor="middle"
                fontSize="1.8"
                fill="var(--text-tertiary)"
              >
                {node.ips.size} IPs
              </text>
            </g>
          );
        })}
      </svg>
      <div className="geo-legend">
        {nodes.map((node) => (
          <div key={node.region} className="geo-legend-item">
            <span className="geo-dot" />
            <span className="geo-region">{node.region}</span>
            <span className="geo-count">{node.ips.size} IPs, {node.flowCount} flows</span>
          </div>
        ))}
      </div>
    </div>
  );
}
