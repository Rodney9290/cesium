import { useState, useMemo } from "react";
import type { CaptureOverview, Flow, Finding } from "../types";
import { Timeline } from "./Timeline";
import { FindingsPanel } from "./FindingsPanel";
import { EvidenceDrawer } from "./EvidenceDrawer";
import { PacketTable } from "./PacketTable";

interface Props {
  capture: CaptureOverview;
  onBack: () => void;
}

type ViewTab = "timeline" | "packets";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatBps(bps: number): string {
  if (bps < 1000) return `${bps.toFixed(0)} bps`;
  if (bps < 1e6) return `${(bps / 1000).toFixed(1)} Kbps`;
  return `${(bps / 1e6).toFixed(1)} Mbps`;
}

function formatDuration(seconds: number): string {
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)}ms`;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  return `${(seconds / 60).toFixed(1)}m`;
}

// Natural-language filter parser
function parseNaturalQuery(
  query: string,
  flows: Flow[],
  allFindings: Finding[],
): Flow[] {
  const q = query.toLowerCase().trim();
  if (!q) return flows;

  // Check for natural-language patterns
  const patterns: { test: RegExp; filter: (f: Flow) => boolean }[] = [
    { test: /slow|latency|delay/, filter: (f) => f.findings.some((fi) => fi.title.toLowerCase().includes("slow") || fi.title.toLowerCase().includes("latency")) },
    { test: /error|problem|issue|fail/, filter: (f) => f.findings.some((fi) => fi.severity === "error") },
    { test: /warning/, filter: (f) => f.findings.some((fi) => fi.severity === "warning") },
    { test: /dns/, filter: (f) => f.protocol === "DNS" || f.events.some((e) => e.kind.startsWith("dns")) },
    { test: /retrans/, filter: (f) => f.events.some((e) => e.kind === "retransmission") },
    { test: /reset|rst/, filter: (f) => f.events.some((e) => e.kind === "reset") },
    { test: /tls|ssl|https|encrypt/, filter: (f) => f.protocol === "TLS" || f.events.some((e) => e.kind.startsWith("tls")) },
    { test: /http(?!s)/, filter: (f) => f.protocol === "HTTP" || f.events.some((e) => e.kind.startsWith("http")) },
    { test: /quic/, filter: (f) => f.protocol === "QUIC" },
    { test: /udp/, filter: (f) => f.protocol === "UDP" || f.protocol === "DNS" || f.protocol === "QUIC" || f.protocol === "MDNS" },
    { test: /tcp/, filter: (f) => f.protocol === "TCP" || f.protocol === "TLS" || f.protocol === "HTTP" },
    { test: /big|large|most data/, filter: (f) => f.bytes > 10000 },
    { test: /many packets|most packets/, filter: (f) => f.packetCount > 10 },
    { test: /no issues|clean|healthy/, filter: (f) => f.findings.length === 0 },
    { test: /has issues|problematic/, filter: (f) => f.findings.length > 0 },
    { test: /duplicate.?ack|dup.?ack/, filter: (f) => f.events.some((e) => e.kind === "duplicate_ack") },
    { test: /out.?of.?order|ooo|reorder/, filter: (f) => f.events.some((e) => e.kind === "out_of_order") },
    { test: /zero.?window/, filter: (f) => f.events.some((e) => e.kind === "zero_window") },
  ];

  for (const { test, filter } of patterns) {
    if (test.test(q)) {
      return flows.filter(filter);
    }
  }

  // Fallback: IP/protocol text search
  return flows.filter(
    (f) =>
      f.dstIp.includes(q) ||
      f.srcIp.includes(q) ||
      f.protocol.toLowerCase().includes(q) ||
      f.srcPort.toString().includes(q) ||
      f.dstPort.toString().includes(q),
  );
}

function exportFindings(capture: CaptureOverview, format: "markdown" | "json") {
  let content: string;
  let filename: string;
  const mime = format === "json" ? "application/json" : "text/markdown";

  if (format === "json") {
    content = JSON.stringify(
      {
        filename: capture.filename,
        totalPackets: capture.totalPackets,
        duration: capture.duration,
        findings: capture.findings,
        flows: capture.flows.map((f) => ({
          srcIp: f.srcIp,
          dstIp: f.dstIp,
          protocol: f.protocol,
          packetCount: f.packetCount,
          bytes: f.bytes,
          stats: f.stats,
          findingCount: f.findings.length,
        })),
      },
      null,
      2,
    );
    filename = `${capture.filename}-report.json`;
  } else {
    const lines = [
      `# Cesium Analysis Report`,
      ``,
      `**File:** ${capture.filename}`,
      `**Packets:** ${capture.totalPackets}`,
      `**Duration:** ${formatDuration(capture.duration)}`,
      `**Flows:** ${capture.flows.length}`,
      `**Findings:** ${capture.findings.length}`,
      ``,
      `---`,
      ``,
    ];
    if (capture.findings.length > 0) {
      lines.push(`## Findings\n`);
      for (const f of capture.findings) {
        lines.push(`### ${f.severity === "error" ? "🔴" : f.severity === "warning" ? "🟡" : "🔵"} ${f.title}`);
        lines.push(`${f.explanation}\n`);
        for (const e of f.evidence) {
          lines.push(`- **${e.label}:** ${e.value} (frames: ${e.frameNumbers.join(", ")})`);
        }
        if (f.caveat) lines.push(`\n> ${f.caveat}`);
        lines.push(`\n*Confidence: ${f.confidence}*\n`);
      }
    }
    content = lines.join("\n");
    filename = `${capture.filename}-report.md`;
  }

  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function CaptureView({ capture, onBack }: Props) {
  const [selectedFlowId, setSelectedFlowId] = useState<string | null>(
    capture.flows[0]?.id ?? null,
  );
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeFilter, setActiveFilter] = useState<string | null>(null);
  const [viewTab, setViewTab] = useState<ViewTab>("timeline");

  const selectedFlow = capture.flows.find((f) => f.id === selectedFlowId);
  const flowFindings = capture.findings.filter(
    (f) => f.flowId === selectedFlowId,
  );

  const filteredFlows = useMemo(() => {
    let flows = capture.flows;

    // Apply pill filter first
    if (activeFilter) {
      const filterMap: Record<string, (f: Flow) => boolean> = {
        slow: (f) => f.findings.some((fi) => fi.title.toLowerCase().includes("slow") || fi.title.toLowerCase().includes("latency")),
        errors: (f) => f.findings.some((fi) => fi.severity === "error"),
        dns: (f) => f.protocol === "DNS" || f.events.some((e) => e.kind.startsWith("dns")),
        retransmissions: (f) => f.events.some((e) => e.kind === "retransmission"),
        tls: (f) => f.protocol === "TLS" || f.events.some((e) => e.kind.startsWith("tls")),
        resets: (f) => f.events.some((e) => e.kind === "reset"),
      };
      const fn = filterMap[activeFilter];
      if (fn) flows = flows.filter(fn);
    }

    // Then apply search/natural-language filter
    return parseNaturalQuery(searchQuery, flows, capture.findings);
  }, [capture.flows, capture.findings, searchQuery, activeFilter]);

  const toggleFilter = (name: string) => {
    setActiveFilter((prev) => (prev === name ? null : name));
  };

  const totalBytes = capture.flows.reduce((sum, f) => sum + f.bytes, 0);

  return (
    <div className="capture-layout">
      {/* Metadata Bar */}
      <div className="metadata-bar">
        <button className="back-btn" onClick={onBack}>
          &larr; Back
        </button>
        <div className="metadata-items">
          <span className="metadata-item">
            <strong>{capture.filename}</strong>
          </span>
          <span className="metadata-item">
            {capture.totalPackets.toLocaleString()} packets
          </span>
          <span className="metadata-item">
            {formatDuration(capture.duration)}
          </span>
          <span className="metadata-item">{formatBytes(totalBytes)}</span>
          <span className="metadata-item">
            {capture.flows.length} flows
          </span>
          <span className="metadata-item">
            {capture.findings.length} finding{capture.findings.length !== 1 ? "s" : ""}
          </span>
        </div>
        <div className="metadata-actions">
          <button
            className="btn-icon"
            title="Export as Markdown"
            onClick={() => exportFindings(capture, "markdown")}
          >
            📋 Export
          </button>
          <button
            className="btn-icon"
            title="Export as JSON"
            onClick={() => exportFindings(capture, "json")}
          >
            {"{ }"}
          </button>
        </div>
      </div>

      {/* Left Sidebar — Connection List */}
      <div className="sidebar">
        <div className="sidebar-header">
          <h2>Connections ({filteredFlows.length})</h2>
          <input
            className="search-box"
            type="text"
            placeholder='Filter: IP, protocol, or "show me slow connections"'
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
        <div className="quick-filters">
          {["slow", "errors", "dns", "retransmissions", "tls", "resets"].map(
            (name) => (
              <button
                key={name}
                className={`filter-pill ${activeFilter === name ? "active" : ""}`}
                onClick={() => toggleFilter(name)}
              >
                {name.charAt(0).toUpperCase() + name.slice(1)}
              </button>
            ),
          )}
        </div>
        <div className="connection-list">
          {filteredFlows.map((flow) => (
            <ConnectionItem
              key={flow.id}
              flow={flow}
              selected={flow.id === selectedFlowId}
              onClick={() => setSelectedFlowId(flow.id)}
            />
          ))}
        </div>
      </div>

      {/* Center — Timeline / Packets */}
      <div className="main-panel">
        <div className="main-panel-header">
          <h2>
            {selectedFlow
              ? `${selectedFlow.srcIp} → ${selectedFlow.dstIp}`
              : "Select a connection"}
          </h2>
          {selectedFlow && (
            <div className="flow-stats">
              <span className="stat-chip">{formatBytes(selectedFlow.bytes)}</span>
              <span className="stat-chip">{formatBps(selectedFlow.stats.throughputBps)}</span>
              <span className="stat-chip">avg {selectedFlow.stats.avgPacketSize.toFixed(0)}B/pkt</span>
              {selectedFlow.stats.rttMs != null && (
                <span className="stat-chip">RTT {selectedFlow.stats.rttMs.toFixed(1)}ms</span>
              )}
            </div>
          )}
          {selectedFlow && (
            <div className="view-tabs">
              <button
                className={`tab-btn ${viewTab === "timeline" ? "active" : ""}`}
                onClick={() => setViewTab("timeline")}
              >
                Timeline
              </button>
              <button
                className={`tab-btn ${viewTab === "packets" ? "active" : ""}`}
                onClick={() => setViewTab("packets")}
              >
                Packets
              </button>
            </div>
          )}
        </div>
        <div className="main-content">
          {selectedFlow ? (
            viewTab === "timeline" ? (
              <Timeline events={selectedFlow.events} />
            ) : (
              <PacketTable packets={selectedFlow.packets} />
            )
          ) : (
            <p style={{ color: "var(--text-tertiary)", padding: 24 }}>
              Select a connection from the sidebar to view its timeline.
            </p>
          )}
        </div>
      </div>

      {/* Right — Findings */}
      <FindingsPanel
        findings={flowFindings}
        onSelectFinding={setSelectedFinding}
      />

      {/* Bottom — Evidence Drawer */}
      {selectedFinding && (
        <EvidenceDrawer
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  );
}

function ConnectionItem({
  flow,
  selected,
  onClick,
}: {
  flow: Flow;
  selected: boolean;
  onClick: () => void;
}) {
  const hasIssues = flow.findings.length > 0;
  const hasErrors = flow.findings.some((f) => f.severity === "error");

  return (
    <div
      className={`connection-item ${selected ? "selected" : ""}`}
      onClick={onClick}
    >
      <div className="connection-host">
        {hasIssues && (
          <span
            className={`connection-indicator ${hasErrors ? "error" : "warning"}`}
          />
        )}
        {flow.dstIp}
      </div>
      <div className="connection-meta">
        {flow.protocol} &middot; {flow.packetCount} pkts &middot;{" "}
        {formatBytes(flow.bytes)}
      </div>
    </div>
  );
}
