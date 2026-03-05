import { useMemo } from "react";
import type { Flow } from "../types";

interface Props {
  flows: Flow[];
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function BandwidthGraph({ flows }: Props) {
  const { buckets, maxBps, labels, totalDuration } = useMemo(() => {
    if (flows.length === 0) return { buckets: [], maxBps: 0, labels: [], totalDuration: 0 };

    const allPackets = flows.flatMap((f) => f.packets);
    if (allPackets.length === 0) return { buckets: [], maxBps: 0, labels: [], totalDuration: 0 };

    const minT = Math.min(...allPackets.map((p) => p.timestamp));
    const maxT = Math.max(...allPackets.map((p) => p.timestamp));
    const duration = maxT - minT || 1;

    const numBuckets = Math.min(100, Math.max(20, allPackets.length / 10));
    const bucketSize = duration / numBuckets;
    const vals = new Array(Math.ceil(numBuckets)).fill(0);

    for (const p of allPackets) {
      const idx = Math.min(Math.floor((p.timestamp - minT) / bucketSize), vals.length - 1);
      vals[idx] += p.length;
    }

    // Convert to bytes per second
    const bps = vals.map((v) => v / bucketSize);
    const maxBps = Math.max(...bps, 1);

    const labels = vals.map((_, i) => {
      const t = i * bucketSize;
      if (t < 1) return `${(t * 1000).toFixed(0)}ms`;
      return `${t.toFixed(1)}s`;
    });

    return { buckets: bps, maxBps, labels, totalDuration: duration };
  }, [flows]);

  if (buckets.length === 0) {
    return <p style={{ color: "var(--text-tertiary)", padding: 16 }}>No data to display.</p>;
  }

  const width = 800;
  const height = 200;
  const padding = { top: 20, right: 20, bottom: 30, left: 60 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const points = buckets.map((v, i) => {
    const x = padding.left + (i / (buckets.length - 1)) * chartW;
    const y = padding.top + chartH - (v / maxBps) * chartH;
    return `${x},${y}`;
  });

  const areaPoints = [
    `${padding.left},${padding.top + chartH}`,
    ...points,
    `${padding.left + chartW},${padding.top + chartH}`,
  ];

  // Y-axis labels
  const yLabels = [0, 0.25, 0.5, 0.75, 1].map((pct) => ({
    y: padding.top + chartH - pct * chartH,
    label: formatBytes(maxBps * pct) + "/s",
  }));

  // X-axis labels (show ~5)
  const step = Math.max(1, Math.floor(buckets.length / 5));
  const xLabels = labels.filter((_, i) => i % step === 0 || i === labels.length - 1).map((label, idx) => ({
    x: padding.left + ((idx * step) / (buckets.length - 1)) * chartW,
    label,
  }));

  return (
    <div className="bandwidth-graph">
      <div className="bw-header">
        <h3>Bandwidth Over Time</h3>
        <span className="bw-duration">Duration: {totalDuration < 1 ? `${(totalDuration * 1000).toFixed(0)}ms` : `${totalDuration.toFixed(1)}s`}</span>
        <span className="bw-peak">Peak: {formatBytes(maxBps)}/s</span>
      </div>
      <svg viewBox={`0 0 ${width} ${height}`} className="bw-svg">
        {/* Grid lines */}
        {yLabels.map((yl, i) => (
          <g key={i}>
            <line x1={padding.left} y1={yl.y} x2={width - padding.right} y2={yl.y} stroke="var(--border-light)" strokeWidth="0.5" />
            <text x={padding.left - 4} y={yl.y + 3} textAnchor="end" fontSize="9" fill="var(--text-tertiary)">{yl.label}</text>
          </g>
        ))}

        {/* Area fill */}
        <polygon points={areaPoints.join(" ")} fill="var(--accent)" opacity="0.1" />

        {/* Line */}
        <polyline points={points.join(" ")} fill="none" stroke="var(--accent)" strokeWidth="1.5" />

        {/* X-axis labels */}
        {xLabels.map((xl, i) => (
          <text key={i} x={xl.x} y={height - 5} textAnchor="middle" fontSize="9" fill="var(--text-tertiary)">{xl.label}</text>
        ))}
      </svg>
    </div>
  );
}
