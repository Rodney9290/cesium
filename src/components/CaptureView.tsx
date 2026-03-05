import { useState, useMemo, useEffect, useRef, useCallback } from "react";
import type { CaptureOverview, Flow, Finding } from "../types";
import type { Bookmark } from "../App";
import { loadSearchHistory, saveSearchQuery } from "../App";
import { Timeline } from "./Timeline";
import { FindingsPanel } from "./FindingsPanel";
import { EvidenceDrawer } from "./EvidenceDrawer";
import { PacketTable } from "./PacketTable";
import { SummaryDashboard } from "./SummaryDashboard";
import { WaterfallChart } from "./WaterfallChart";

interface Props {
  capture: CaptureOverview;
  onBack: () => void;
  bookmarks: Bookmark[];
  onToggleBookmark: (flowId: string, label: string) => void;
}

type ViewTab = "timeline" | "packets" | "compare" | "dashboard" | "waterfall";

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

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text);
}

function Copyable({ text, children }: { text: string; children?: React.ReactNode }) {
  const [copied, setCopied] = useState(false);
  return (
    <span
      className="copyable"
      title="Click to copy"
      onClick={(e) => {
        e.stopPropagation();
        copyToClipboard(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}
    >
      {children ?? text}
      {copied && <span className="copied-badge">Copied</span>}
    </span>
  );
}

function resolveIp(ip: string, hostnames: Record<string, string>): string {
  return hostnames[ip] || ip;
}

function Sparkline({ packets }: { packets: { timestamp: number; length: number }[] }) {
  if (packets.length < 2) return null;
  const buckets = 20;
  const minT = packets[0].timestamp;
  const maxT = packets[packets.length - 1].timestamp;
  const range = maxT - minT || 1;
  const vals = new Array(buckets).fill(0);
  for (const p of packets) {
    const idx = Math.min(Math.floor(((p.timestamp - minT) / range) * buckets), buckets - 1);
    vals[idx] += p.length;
  }
  const maxV = Math.max(...vals, 1);
  const w = 60;
  const h = 16;
  const points = vals.map((v, i) => `${(i / (buckets - 1)) * w},${h - (v / maxV) * h}`).join(" ");
  return (
    <svg width={w} height={h} className="sparkline">
      <polyline points={points} fill="none" stroke="var(--accent)" strokeWidth="1.5" />
    </svg>
  );
}

// Custom alert rules
interface AlertRule {
  id: string;
  name: string;
  condition: string;
  enabled: boolean;
}

const ALERT_RULES_KEY = "cesium-alert-rules";

function loadAlertRules(): AlertRule[] {
  try {
    return JSON.parse(localStorage.getItem(ALERT_RULES_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveAlertRules(rules: AlertRule[]) {
  localStorage.setItem(ALERT_RULES_KEY, JSON.stringify(rules));
}

function evaluateRule(rule: AlertRule, flow: Flow): boolean {
  const c = rule.condition.toLowerCase();
  if (c.includes("retransmission") && flow.events.some((e) => e.kind === "retransmission")) return true;
  if (c.includes("reset") && flow.events.some((e) => e.kind === "reset")) return true;
  if (c.includes("high rtt") && flow.stats.rttMs != null && flow.stats.rttMs > 100) return true;
  if (c.includes("large") && flow.bytes > 100000) return true;
  if (c.includes("zero window") && flow.events.some((e) => e.kind === "zero_window")) return true;
  if (c.includes("anomaly") && flow.anomalyScore > 50) return true;
  const bytesMatch = c.match(/bytes\s*>\s*(\d+)/);
  if (bytesMatch && flow.bytes > Number(bytesMatch[1])) return true;
  const rttMatch = c.match(/rtt\s*>\s*(\d+)/);
  if (rttMatch && flow.stats.rttMs != null && flow.stats.rttMs > Number(rttMatch[1])) return true;
  const packetsMatch = c.match(/packets\s*>\s*(\d+)/);
  if (packetsMatch && flow.packetCount > Number(packetsMatch[1])) return true;
  return false;
}

function parseNaturalQuery(
  query: string,
  flows: Flow[],
  _allFindings: Finding[],
): Flow[] {
  const q = query.toLowerCase().trim();
  if (!q) return flows;

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
    { test: /anomal|unusual|suspicious/, filter: (f) => f.anomalyScore > 30 },
    { test: /bookmarked|saved/, filter: () => false }, // handled externally
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
          srcIp: f.srcIp, dstIp: f.dstIp, protocol: f.protocol,
          packetCount: f.packetCount, bytes: f.bytes, stats: f.stats,
          anomalyScore: f.anomalyScore, findingCount: f.findings.length,
        })),
      },
      null, 2,
    );
    filename = `${capture.filename}-report.json`;
  } else {
    const lines = [
      `# Cesium Analysis Report`, ``,
      `**File:** ${capture.filename}`,
      `**Packets:** ${capture.totalPackets}`,
      `**Duration:** ${formatDuration(capture.duration)}`,
      `**Flows:** ${capture.flows.length}`,
      `**Findings:** ${capture.findings.length}`, ``, `---`, ``,
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

type GroupMode = "none" | "destination" | "protocol";

function groupFlows(flows: Flow[], mode: GroupMode, hostnames: Record<string, string>): Map<string, Flow[]> {
  if (mode === "none") return new Map([["", flows]]);
  const map = new Map<string, Flow[]>();
  for (const f of flows) {
    const key = mode === "destination" ? (hostnames[f.dstIp] || f.dstIp) : f.protocol;
    const arr = map.get(key) || [];
    arr.push(f);
    map.set(key, arr);
  }
  return map;
}

export function CaptureView({ capture, onBack, bookmarks, onToggleBookmark }: Props) {
  const [selectedFlowId, setSelectedFlowId] = useState<string | null>(
    capture.flows[0]?.id ?? null,
  );
  const [compareFlowId, setCompareFlowId] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [globalSearch, setGlobalSearch] = useState("");
  const [activeFilter, setActiveFilter] = useState<string | null>(null);
  const [viewTab, setViewTab] = useState<ViewTab>("timeline");
  const [groupMode, setGroupMode] = useState<GroupMode>("none");
  const [timeRange, setTimeRange] = useState<[number, number] | null>(null);
  const [showSearchHistory, setShowSearchHistory] = useState(false);
  const [alertRules, setAlertRules] = useState<AlertRule[]>(loadAlertRules);
  const [showRuleEditor, setShowRuleEditor] = useState(false);
  const [newRuleName, setNewRuleName] = useState("");
  const [newRuleCondition, setNewRuleCondition] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);
  const connectionListRef = useRef<HTMLDivElement>(null);

  const hostnames = capture.hostnames || {};
  const searchHistory = loadSearchHistory();

  const selectedFlow = capture.flows.find((f) => f.id === selectedFlowId);
  const compareFlow = capture.flows.find((f) => f.id === compareFlowId);
  const flowFindings = capture.findings.filter((f) => f.flowId === selectedFlowId);

  // Alert rule violations
  const ruleViolations = useMemo(() => {
    const violations: Map<string, string[]> = new Map();
    for (const rule of alertRules) {
      if (!rule.enabled) continue;
      for (const flow of capture.flows) {
        if (evaluateRule(rule, flow)) {
          const arr = violations.get(flow.id) || [];
          arr.push(rule.name);
          violations.set(flow.id, arr);
        }
      }
    }
    return violations;
  }, [alertRules, capture.flows]);

  const globalFiltered = useMemo(() => {
    if (!globalSearch.trim()) return capture.flows;
    const q = globalSearch.toLowerCase();
    return capture.flows.filter((f) => {
      const hostSrc = hostnames[f.srcIp] || "";
      const hostDst = hostnames[f.dstIp] || "";
      return (
        f.srcIp.includes(q) || f.dstIp.includes(q) ||
        hostSrc.toLowerCase().includes(q) || hostDst.toLowerCase().includes(q) ||
        f.protocol.toLowerCase().includes(q) ||
        f.findings.some((fi) => fi.title.toLowerCase().includes(q) || fi.explanation.toLowerCase().includes(q)) ||
        f.events.some((e) => e.label.toLowerCase().includes(q))
      );
    });
  }, [capture.flows, globalSearch, hostnames]);

  const filteredFlows = useMemo(() => {
    let flows = globalFiltered;

    if (timeRange) {
      flows = flows.filter((f) => f.startTime >= timeRange[0] && f.startTime <= timeRange[1]);
    }

    if (activeFilter) {
      const filterMap: Record<string, (f: Flow) => boolean> = {
        slow: (f) => f.findings.some((fi) => fi.title.toLowerCase().includes("slow") || fi.title.toLowerCase().includes("latency")),
        errors: (f) => f.findings.some((fi) => fi.severity === "error"),
        dns: (f) => f.protocol === "DNS" || f.events.some((e) => e.kind.startsWith("dns")),
        retransmissions: (f) => f.events.some((e) => e.kind === "retransmission"),
        tls: (f) => f.protocol === "TLS" || f.events.some((e) => e.kind.startsWith("tls")),
        resets: (f) => f.events.some((e) => e.kind === "reset"),
        bookmarked: (f) => bookmarks.some((b) => b.flowId === f.id),
        anomalous: (f) => f.anomalyScore > 30,
        alerts: (f) => ruleViolations.has(f.id),
      };
      const fn = filterMap[activeFilter];
      if (fn) flows = flows.filter(fn);
    }

    return parseNaturalQuery(searchQuery, flows, capture.findings);
  }, [globalFiltered, capture.findings, searchQuery, activeFilter, timeRange, bookmarks, ruleViolations]);

  const grouped = useMemo(
    () => groupFlows(filteredFlows, groupMode, hostnames),
    [filteredFlows, groupMode, hostnames],
  );

  const toggleFilter = (name: string) => {
    setActiveFilter((prev) => (prev === name ? null : name));
  };

  const totalBytes = capture.flows.reduce((sum, f) => sum + f.bytes, 0);

  // Save search on Enter
  const handleSearchKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && searchQuery.trim()) {
      saveSearchQuery(searchQuery.trim());
      setShowSearchHistory(false);
    }
    if (e.key === "Escape") {
      setShowSearchHistory(false);
    }
  };

  const handleAddRule = () => {
    if (!newRuleName.trim() || !newRuleCondition.trim()) return;
    const rule: AlertRule = {
      id: Date.now().toString(),
      name: newRuleName.trim(),
      condition: newRuleCondition.trim(),
      enabled: true,
    };
    const next = [...alertRules, rule];
    setAlertRules(next);
    saveAlertRules(next);
    setNewRuleName("");
    setNewRuleCondition("");
  };

  const toggleRule = (id: string) => {
    const next = alertRules.map((r) => r.id === id ? { ...r, enabled: !r.enabled } : r);
    setAlertRules(next);
    saveAlertRules(next);
  };

  const deleteRule = (id: string) => {
    const next = alertRules.filter((r) => r.id !== id);
    setAlertRules(next);
    saveAlertRules(next);
  };

  // Keyboard navigation
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "/" && document.activeElement?.tagName !== "INPUT") {
        e.preventDefault();
        searchRef.current?.focus();
        setShowSearchHistory(true);
        return;
      }
      if (e.key === "Escape") {
        (document.activeElement as HTMLElement)?.blur();
        setSelectedFinding(null);
        setShowSearchHistory(false);
        setShowRuleEditor(false);
        if (compareFlowId) setCompareFlowId(null);
        return;
      }
      if (document.activeElement?.tagName === "INPUT" || document.activeElement?.tagName === "SELECT") return;

      if (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "j" || e.key === "k") {
        e.preventDefault();
        const idx = filteredFlows.findIndex((f) => f.id === selectedFlowId);
        const next = (e.key === "ArrowDown" || e.key === "k") ? idx + 1 : idx - 1;
        if (next >= 0 && next < filteredFlows.length) {
          setSelectedFlowId(filteredFlows[next].id);
          const el = connectionListRef.current?.querySelector(`[data-flow-id="${filteredFlows[next].id}"]`);
          el?.scrollIntoView({ block: "nearest" });
        }
        return;
      }
      if (e.key === "b" && selectedFlowId) {
        const flow = capture.flows.find((f) => f.id === selectedFlowId);
        if (flow) onToggleBookmark(flow.id, `${flow.dstIp}:${flow.dstPort}`);
      }
      if (e.key === "d") setViewTab("dashboard");
      else if (e.key === "t") setViewTab("timeline");
      else if (e.key === "p") setViewTab("packets");
      else if (e.key === "w") setViewTab("waterfall");
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [filteredFlows, selectedFlowId, compareFlowId, capture.flows, onToggleBookmark]);

  const captureStart = capture.flows.length > 0
    ? Math.min(...capture.flows.map((f) => f.startTime)) : 0;
  const captureEnd = capture.flows.length > 0
    ? Math.max(...capture.flows.map((f) => f.endTime)) : 0;

  const handleCompareSelect = useCallback((flowId: string) => {
    if (flowId === selectedFlowId) return;
    setCompareFlowId(flowId);
    setViewTab("compare");
  }, [selectedFlowId]);

  return (
    <div className="capture-layout">
      {/* Metadata Bar */}
      <div className="metadata-bar">
        <button className="back-btn" onClick={onBack}>&larr; Back</button>
        <div className="metadata-items">
          <span className="metadata-item"><strong>{capture.filename}</strong></span>
          <span className="metadata-item">{capture.totalPackets.toLocaleString()} packets</span>
          <span className="metadata-item">{formatDuration(capture.duration)}</span>
          <span className="metadata-item">{formatBytes(totalBytes)}</span>
          <span className="metadata-item">{capture.flows.length} flows</span>
          <span className="metadata-item">
            {capture.findings.length} finding{capture.findings.length !== 1 ? "s" : ""}
          </span>
        </div>
        <input
          className="global-search"
          type="text"
          placeholder="Search everything... (hosts, IPs, findings)"
          value={globalSearch}
          onChange={(e) => setGlobalSearch(e.target.value)}
        />
        <div className="metadata-actions">
          <button
            className={`btn-icon ${viewTab === "waterfall" ? "active" : ""}`}
            onClick={() => setViewTab(viewTab === "waterfall" ? "timeline" : "waterfall")}
            title="Waterfall"
          >Waterfall</button>
          <button
            className={`btn-icon ${viewTab === "dashboard" ? "active" : ""}`}
            onClick={() => setViewTab(viewTab === "dashboard" ? "timeline" : "dashboard")}
            title="Dashboard"
          >Dashboard</button>
          <button
            className={`btn-icon ${showRuleEditor ? "active" : ""}`}
            onClick={() => setShowRuleEditor(!showRuleEditor)}
            title="Alert Rules"
          >Alerts</button>
          <button className="btn-icon" title="Export as Markdown" onClick={() => exportFindings(capture, "markdown")}>Export</button>
          <button className="btn-icon" title="Export as JSON" onClick={() => exportFindings(capture, "json")}>{"{ }"}</button>
        </div>
      </div>

      {/* Alert Rule Editor */}
      {showRuleEditor && (
        <div className="rule-editor">
          <div className="rule-editor-header">
            <h3>Alert Rules</h3>
            <span className="rule-hint">Conditions: retransmission, reset, high rtt, large, zero window, anomaly, bytes &gt; N, rtt &gt; N, packets &gt; N</span>
          </div>
          <div className="rule-add">
            <input placeholder="Rule name" value={newRuleName} onChange={(e) => setNewRuleName(e.target.value)} />
            <input placeholder="Condition (e.g. rtt > 100)" value={newRuleCondition} onChange={(e) => setNewRuleCondition(e.target.value)} />
            <button className="btn-icon" onClick={handleAddRule}>Add</button>
          </div>
          <div className="rule-list">
            {alertRules.map((r) => (
              <div key={r.id} className="rule-item">
                <label>
                  <input type="checkbox" checked={r.enabled} onChange={() => toggleRule(r.id)} />
                  <strong>{r.name}</strong> — {r.condition}
                  {r.enabled && ` (${capture.flows.filter((f) => evaluateRule(r, f)).length} matches)`}
                </label>
                <button className="rule-delete" onClick={() => deleteRule(r.id)}>x</button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Left Sidebar */}
      <div className="sidebar">
        <div className="sidebar-header">
          <h2>Connections ({filteredFlows.length})</h2>
          <div style={{ position: "relative" }}>
            <input
              ref={searchRef}
              className="search-box"
              type="text"
              placeholder='Filter: IP, protocol, or "show me slow connections" (press /)'
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onFocus={() => setShowSearchHistory(true)}
              onBlur={() => setTimeout(() => setShowSearchHistory(false), 200)}
              onKeyDown={handleSearchKeyDown}
            />
            {showSearchHistory && searchHistory.length > 0 && (
              <div className="search-history">
                {searchHistory.slice(0, 8).map((q) => (
                  <div
                    key={q}
                    className="search-history-item"
                    onMouseDown={() => {
                      setSearchQuery(q);
                      setShowSearchHistory(false);
                    }}
                  >{q}</div>
                ))}
              </div>
            )}
          </div>
        </div>
        <div className="quick-filters">
          {["slow", "errors", "dns", "retransmissions", "tls", "resets", "bookmarked", "anomalous", "alerts"].map(
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
          <select
            className="group-select"
            value={groupMode}
            onChange={(e) => setGroupMode(e.target.value as GroupMode)}
          >
            <option value="none">No grouping</option>
            <option value="destination">By destination</option>
            <option value="protocol">By protocol</option>
          </select>
        </div>
        {captureEnd > captureStart && (
          <div className="time-range-bar">
            <label>Time range</label>
            <input
              type="range" min={0} max={1000} defaultValue={0}
              className="time-slider"
              onChange={(e) => {
                const pct = Number(e.target.value) / 1000;
                const rangeStart = captureStart + pct * (captureEnd - captureStart);
                setTimeRange(pct > 0 ? [rangeStart, captureEnd] : null);
              }}
            />
            {timeRange && (
              <button className="clear-range" onClick={() => setTimeRange(null)}>Clear</button>
            )}
          </div>
        )}
        <div className="connection-list" ref={connectionListRef}>
          {Array.from(grouped.entries()).map(([group, flows]) => (
            <div key={group}>
              {groupMode !== "none" && (
                <div className="group-header">{group} ({flows.length})</div>
              )}
              {flows.map((flow) => (
                <ConnectionItem
                  key={flow.id}
                  flow={flow}
                  hostnames={hostnames}
                  selected={flow.id === selectedFlowId}
                  comparing={flow.id === compareFlowId}
                  bookmarked={bookmarks.some((b) => b.flowId === flow.id)}
                  ruleViolations={ruleViolations.get(flow.id)}
                  onClick={() => setSelectedFlowId(flow.id)}
                  onCompare={() => handleCompareSelect(flow.id)}
                  onBookmark={() => onToggleBookmark(flow.id, `${flow.dstIp}:${flow.dstPort}`)}
                />
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* Center */}
      <div className="main-panel">
        <div className="main-panel-header">
          <h2>
            {selectedFlow
              ? <>
                  <Copyable text={selectedFlow.srcIp}>{resolveIp(selectedFlow.srcIp, hostnames)}</Copyable>
                  {" → "}
                  <Copyable text={selectedFlow.dstIp}>{resolveIp(selectedFlow.dstIp, hostnames)}</Copyable>
                </>
              : "Select a connection"}
          </h2>
          {selectedFlow && (
            <div className="flow-stats">
              <span className="stat-chip">{formatBytes(selectedFlow.bytes)}</span>
              <span className="stat-chip">{formatBps(selectedFlow.stats.throughputBps)}</span>
              {selectedFlow.stats.rttMs != null && (
                <span className="stat-chip">RTT {selectedFlow.stats.rttMs.toFixed(1)}ms</span>
              )}
              <span className={`stat-chip ${selectedFlow.anomalyScore > 50 ? "anomaly-high" : selectedFlow.anomalyScore > 20 ? "anomaly-med" : ""}`}>
                Anomaly: {selectedFlow.anomalyScore.toFixed(0)}
              </span>
              <Sparkline packets={selectedFlow.packets} />
            </div>
          )}
          {selectedFlow && (
            <div className="view-tabs">
              {(["timeline", "packets", "waterfall", "dashboard"] as ViewTab[]).map((t) => (
                <button key={t} className={`tab-btn ${viewTab === t ? "active" : ""}`} onClick={() => setViewTab(t)}>
                  {t.charAt(0).toUpperCase() + t.slice(1)}
                </button>
              ))}
              {compareFlow && (
                <button className={`tab-btn ${viewTab === "compare" ? "active" : ""}`} onClick={() => setViewTab("compare")}>Compare</button>
              )}
            </div>
          )}
        </div>
        <div className="main-content">
          {viewTab === "dashboard" ? (
            <SummaryDashboard capture={capture} hostnames={hostnames} />
          ) : viewTab === "waterfall" ? (
            <WaterfallChart
              flows={filteredFlows}
              hostnames={hostnames}
              selectedFlowId={selectedFlowId}
              onSelectFlow={setSelectedFlowId}
            />
          ) : selectedFlow ? (
            viewTab === "timeline" ? (
              <Timeline events={selectedFlow.events} />
            ) : viewTab === "packets" ? (
              <PacketTable packets={selectedFlow.packets} />
            ) : viewTab === "compare" && compareFlow ? (
              <div className="compare-view">
                <div className="compare-col">
                  <h3><Copyable text={selectedFlow.dstIp}>{resolveIp(selectedFlow.dstIp, hostnames)}</Copyable></h3>
                  <div className="compare-stats">
                    <span>{formatBytes(selectedFlow.bytes)}</span>
                    <span>{selectedFlow.packetCount} pkts</span>
                    {selectedFlow.stats.rttMs != null && <span>RTT {selectedFlow.stats.rttMs.toFixed(1)}ms</span>}
                    <span>Anomaly: {selectedFlow.anomalyScore.toFixed(0)}</span>
                  </div>
                  <Timeline events={selectedFlow.events} />
                </div>
                <div className="compare-col">
                  <h3><Copyable text={compareFlow.dstIp}>{resolveIp(compareFlow.dstIp, hostnames)}</Copyable></h3>
                  <div className="compare-stats">
                    <span>{formatBytes(compareFlow.bytes)}</span>
                    <span>{compareFlow.packetCount} pkts</span>
                    {compareFlow.stats.rttMs != null && <span>RTT {compareFlow.stats.rttMs.toFixed(1)}ms</span>}
                    <span>Anomaly: {compareFlow.anomalyScore.toFixed(0)}</span>
                  </div>
                  <Timeline events={compareFlow.events} />
                </div>
              </div>
            ) : (
              <Timeline events={selectedFlow.events} />
            )
          ) : (
            <p style={{ color: "var(--text-tertiary)", padding: 24 }}>
              Select a connection from the sidebar to view its timeline.
            </p>
          )}
        </div>
      </div>

      <FindingsPanel findings={flowFindings} onSelectFinding={setSelectedFinding} />

      {selectedFinding && (
        <EvidenceDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </div>
  );
}

function ConnectionItem({
  flow, hostnames, selected, comparing, bookmarked, ruleViolations,
  onClick, onCompare, onBookmark,
}: {
  flow: Flow;
  hostnames: Record<string, string>;
  selected: boolean;
  comparing: boolean;
  bookmarked: boolean;
  ruleViolations?: string[];
  onClick: () => void;
  onCompare: () => void;
  onBookmark: () => void;
}) {
  const hasIssues = flow.findings.length > 0;
  const hasErrors = flow.findings.some((f) => f.severity === "error");

  return (
    <div
      className={`connection-item ${selected ? "selected" : ""} ${comparing ? "comparing" : ""}`}
      onClick={onClick}
      data-flow-id={flow.id}
    >
      <div className="connection-host">
        {hasIssues && (
          <span className={`connection-indicator ${hasErrors ? "error" : "warning"}`} />
        )}
        {bookmarked && <span className="bookmark-star" title="Bookmarked">*</span>}
        <Copyable text={flow.dstIp}>{resolveIp(flow.dstIp, hostnames)}</Copyable>
        {flow.anomalyScore > 30 && (
          <span className="anomaly-badge" title={`Anomaly score: ${flow.anomalyScore.toFixed(0)}`}>
            {flow.anomalyScore.toFixed(0)}
          </span>
        )}
      </div>
      <div className="connection-meta">
        {flow.protocol} &middot; {flow.packetCount} pkts &middot; {formatBytes(flow.bytes)}
        <Sparkline packets={flow.packets} />
        {ruleViolations && ruleViolations.length > 0 && (
          <span className="rule-alert-badge" title={ruleViolations.join(", ")}>!</span>
        )}
        <button
          className="compare-btn"
          title="Compare with selected"
          onClick={(e) => { e.stopPropagation(); onCompare(); }}
        >vs</button>
        <button
          className="bookmark-btn"
          title={bookmarked ? "Remove bookmark" : "Bookmark"}
          onClick={(e) => { e.stopPropagation(); onBookmark(); }}
        >{bookmarked ? "x" : "+"}</button>
      </div>
    </div>
  );
}
