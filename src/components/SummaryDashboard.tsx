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

export function SummaryDashboard({ capture, hostnames }: Props) {
  const stats = useMemo(() => {
    const protocolCounts: Record<string, number> = {};
    const dstTraffic: Record<string, number> = {};
    let totalErrors = 0;
    let totalWarnings = 0;
    let totalBytes = 0;

    for (const f of capture.flows) {
      protocolCounts[f.protocol] = (protocolCounts[f.protocol] || 0) + 1;
      const dstLabel = hostnames[f.dstIp] || f.dstIp;
      dstTraffic[dstLabel] = (dstTraffic[dstLabel] || 0) + f.bytes;
      totalBytes += f.bytes;
    }

    for (const f of capture.findings) {
      if (f.severity === "error") totalErrors++;
      else if (f.severity === "warning") totalWarnings++;
    }

    const topTalkers = Object.entries(dstTraffic)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

    const protocols = Object.entries(protocolCounts)
      .sort((a, b) => b[1] - a[1]);

    const errorRate = capture.flows.length > 0
      ? ((totalErrors + totalWarnings) / capture.flows.length * 100).toFixed(1)
      : "0";

    return { topTalkers, protocols, totalErrors, totalWarnings, totalBytes, errorRate };
  }, [capture, hostnames]);

  return (
    <div className="dashboard">
      <div className="dashboard-grid">
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
            <span className="stat-label">Connections</span>
            <span className="stat-value">{capture.flows.length}</span>
          </div>
          <div className="dashboard-stat">
            <span className="stat-label">Error Rate</span>
            <span className="stat-value">{stats.errorRate}%</span>
          </div>
          <div className="dashboard-stat">
            <span className="stat-label">Errors</span>
            <span className="stat-value error-text">{stats.totalErrors}</span>
          </div>
          <div className="dashboard-stat">
            <span className="stat-label">Warnings</span>
            <span className="stat-value warning-text">{stats.totalWarnings}</span>
          </div>
        </div>

        <div className="dashboard-card">
          <h3>Top Destinations</h3>
          <div className="dashboard-bar-list">
            {stats.topTalkers.map(([host, bytes]) => (
              <div key={host} className="bar-item">
                <div className="bar-label">{host}</div>
                <div className="bar-track">
                  <div
                    className="bar-fill"
                    style={{
                      width: `${(bytes / stats.topTalkers[0][1]) * 100}%`,
                    }}
                  />
                </div>
                <div className="bar-value">{formatBytes(bytes)}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="dashboard-card">
          <h3>Protocol Breakdown</h3>
          <div className="dashboard-bar-list">
            {stats.protocols.map(([proto, count]) => (
              <div key={proto} className="bar-item">
                <div className="bar-label">
                  <span className={`proto-badge ${proto.toLowerCase()}`}>{proto}</span>
                </div>
                <div className="bar-track">
                  <div
                    className="bar-fill protocol"
                    style={{
                      width: `${(count / stats.protocols[0][1]) * 100}%`,
                    }}
                  />
                </div>
                <div className="bar-value">{count} flows</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
