import { useMemo } from "react";
import type { CaptureOverview } from "../types";

interface Props {
  capture: CaptureOverview;
  hostnames: Record<string, string>;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDuration(seconds: number): string {
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)}ms`;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  return `${(seconds / 60).toFixed(1)}m`;
}

export function SummaryDashboard({ capture, hostnames }: Props) {
  const stats = useMemo(() => {
    const protocolCounts: Record<string, number> = {};
    const protocolBytes: Record<string, number> = {};
    const dstTraffic: Record<string, number> = {};
    const srcTraffic: Record<string, number> = {};
    const portCounts: Record<number, number> = {};
    let totalErrors = 0;
    let totalWarnings = 0;
    let totalBytes = 0;
    let totalRetrans = 0;
    let totalResets = 0;
    let rttSum = 0;
    let rttCount = 0;
    let maxAnomaly = 0;

    for (const f of capture.flows) {
      protocolCounts[f.protocol] = (protocolCounts[f.protocol] || 0) + 1;
      protocolBytes[f.protocol] = (protocolBytes[f.protocol] || 0) + f.bytes;
      const dstLabel = hostnames[f.dstIp] || f.dstIp;
      const srcLabel = hostnames[f.srcIp] || f.srcIp;
      dstTraffic[dstLabel] = (dstTraffic[dstLabel] || 0) + f.bytes;
      srcTraffic[srcLabel] = (srcTraffic[srcLabel] || 0) + f.bytes;
      totalBytes += f.bytes;
      if (f.dstPort) portCounts[f.dstPort] = (portCounts[f.dstPort] || 0) + 1;
      totalRetrans += f.events.filter((e) => e.kind === "retransmission").length;
      totalResets += f.events.filter((e) => e.kind === "reset").length;
      if (f.stats.rttMs != null) { rttSum += f.stats.rttMs; rttCount++; }
      if (f.anomalyScore > maxAnomaly) maxAnomaly = f.anomalyScore;
    }

    for (const f of capture.findings) {
      if (f.severity === "error") totalErrors++;
      else if (f.severity === "warning") totalWarnings++;
    }

    const topDst = Object.entries(dstTraffic).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const topSrc = Object.entries(srcTraffic).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const protocols = Object.entries(protocolCounts).sort((a, b) => b[1] - a[1]);
    const protocolByBytes = Object.entries(protocolBytes).sort((a, b) => b[1] - a[1]);
    const topPorts = Object.entries(portCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);

    const errorRate = capture.flows.length > 0
      ? ((totalErrors + totalWarnings) / capture.flows.length * 100).toFixed(1)
      : "0";
    const avgRtt = rttCount > 0 ? rttSum / rttCount : null;

    return {
      topDst, topSrc, protocols, protocolByBytes, topPorts,
      totalErrors, totalWarnings, totalBytes, errorRate,
      totalRetrans, totalResets, avgRtt, maxAnomaly,
    };
  }, [capture, hostnames]);

  return (
    <div className="dashboard">
      <div className="dashboard-grid">
        {/* Overview Stats */}
        <div className="dashboard-card">
          <h3>Overview</h3>
          <div className="dashboard-stat">
            <span className="stat-label">Total Packets</span>
            <span className="stat-value">{capture.totalPackets.toLocaleString()}</span>
          </div>
          <div className="dashboard-stat">
            <span className="stat-label">Total Traffic</span>
            <span className="stat-value">{formatBytes(stats.totalBytes)}</span>
          </div>
          <div className="dashboard-stat">
            <span className="stat-label">Duration</span>
            <span className="stat-value">{formatDuration(capture.duration)}</span>
          </div>
          <div className="dashboard-stat">
            <span className="stat-label">Connections</span>
            <span className="stat-value">{capture.flows.length}</span>
          </div>
          <div className="dashboard-stat">
            <span className="stat-label">Error Rate</span>
            <span className="stat-value">{stats.errorRate}%</span>
          </div>
          <div className="dashboard-stat">
            <span className="stat-label">Avg RTT</span>
            <span className="stat-value">{stats.avgRtt != null ? `${stats.avgRtt.toFixed(1)}ms` : "-"}</span>
          </div>
        </div>

        {/* Health Indicators */}
        <div className="dashboard-card">
          <h3>Health Indicators</h3>
          <div className="dashboard-bar-list">
            <div className="bar-item">
              <div className="bar-label">Errors</div>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${Math.min((stats.totalErrors / Math.max(capture.findings.length, 1)) * 100, 100)}%`, background: "var(--error)" }} />
              </div>
              <div className="bar-value error-text">{stats.totalErrors}</div>
            </div>
            <div className="bar-item">
              <div className="bar-label">Warnings</div>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${Math.min((stats.totalWarnings / Math.max(capture.findings.length, 1)) * 100, 100)}%`, background: "var(--warning)" }} />
              </div>
              <div className="bar-value warning-text">{stats.totalWarnings}</div>
            </div>
            <div className="bar-item">
              <div className="bar-label">Retransmissions</div>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${Math.min(stats.totalRetrans * 5, 100)}%`, background: "var(--warning)" }} />
              </div>
              <div className="bar-value">{stats.totalRetrans}</div>
            </div>
            <div className="bar-item">
              <div className="bar-label">Resets</div>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${Math.min(stats.totalResets * 10, 100)}%`, background: "var(--error)" }} />
              </div>
              <div className="bar-value">{stats.totalResets}</div>
            </div>
            <div className="bar-item">
              <div className="bar-label">Max Anomaly</div>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${stats.maxAnomaly}%`, background: stats.maxAnomaly > 50 ? "var(--error)" : stats.maxAnomaly > 20 ? "var(--warning)" : "var(--success)" }} />
              </div>
              <div className="bar-value">{stats.maxAnomaly.toFixed(0)}</div>
            </div>
          </div>
        </div>

        {/* Top Destinations */}
        <div className="dashboard-card">
          <h3>Top Destinations</h3>
          <div className="dashboard-bar-list">
            {stats.topDst.map(([host, bytes]) => (
              <div key={host} className="bar-item">
                <div className="bar-label">{host}</div>
                <div className="bar-track">
                  <div className="bar-fill" style={{ width: `${(bytes / stats.topDst[0][1]) * 100}%` }} />
                </div>
                <div className="bar-value">{formatBytes(bytes)}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Sources */}
        <div className="dashboard-card">
          <h3>Top Sources</h3>
          <div className="dashboard-bar-list">
            {stats.topSrc.map(([host, bytes]) => (
              <div key={host} className="bar-item">
                <div className="bar-label">{host}</div>
                <div className="bar-track">
                  <div className="bar-fill" style={{ width: `${(bytes / stats.topSrc[0][1]) * 100}%` }} />
                </div>
                <div className="bar-value">{formatBytes(bytes)}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Protocol Hierarchy (by flow count) */}
        <div className="dashboard-card">
          <h3>Protocol Hierarchy (by flows)</h3>
          <div className="dashboard-bar-list">
            {stats.protocols.map(([proto, count]) => (
              <div key={proto} className="bar-item">
                <div className="bar-label">
                  <span className={`proto-badge ${proto.toLowerCase()}`}>{proto}</span>
                </div>
                <div className="bar-track">
                  <div className="bar-fill protocol" style={{ width: `${(count / stats.protocols[0][1]) * 100}%` }} />
                </div>
                <div className="bar-value">{count} flows</div>
              </div>
            ))}
          </div>
        </div>

        {/* Protocol by Bytes */}
        <div className="dashboard-card">
          <h3>Protocol Hierarchy (by bytes)</h3>
          <div className="dashboard-bar-list">
            {stats.protocolByBytes.map(([proto, bytes]) => (
              <div key={proto} className="bar-item">
                <div className="bar-label">
                  <span className={`proto-badge ${proto.toLowerCase()}`}>{proto}</span>
                </div>
                <div className="bar-track">
                  <div className="bar-fill protocol" style={{ width: `${(bytes / stats.protocolByBytes[0][1]) * 100}%` }} />
                </div>
                <div className="bar-value">{formatBytes(bytes)}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Ports */}
        <div className="dashboard-card">
          <h3>Top Destination Ports</h3>
          <div className="dashboard-bar-list">
            {stats.topPorts.map(([port, count]) => {
              const portNames: Record<string, string> = {
                "80": "HTTP", "443": "HTTPS", "53": "DNS", "22": "SSH",
                "21": "FTP", "25": "SMTP", "110": "POP3", "143": "IMAP",
                "3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis",
                "8080": "HTTP-Alt", "8443": "HTTPS-Alt",
              };
              return (
                <div key={port} className="bar-item">
                  <div className="bar-label">{port}{portNames[port] ? ` (${portNames[port]})` : ""}</div>
                  <div className="bar-track">
                    <div className="bar-fill" style={{ width: `${(count / stats.topPorts[0][1]) * 100}%` }} />
                  </div>
                  <div className="bar-value">{count}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
