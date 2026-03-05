import { useState } from "react";
import type { CaptureOverview, Flow, Finding } from "../types";
import { Timeline } from "./Timeline";
import { FindingsPanel } from "./FindingsPanel";
import { EvidenceDrawer } from "./EvidenceDrawer";

interface Props {
  capture: CaptureOverview;
  onBack: () => void;
}

export function CaptureView({ capture, onBack }: Props) {
  const [selectedFlowId, setSelectedFlowId] = useState<string | null>(
    capture.flows[0]?.id ?? null,
  );
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [searchQuery, setSearchQuery] = useState("");

  const selectedFlow = capture.flows.find((f) => f.id === selectedFlowId);
  const flowFindings = capture.findings.filter(
    (f) => f.flowId === selectedFlowId,
  );

  const filteredFlows = capture.flows.filter((flow) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      flow.dstIp.includes(q) ||
      flow.srcIp.includes(q) ||
      flow.protocol.toLowerCase().includes(q)
    );
  });

  return (
    <div className="capture-layout">
      {/* Left Sidebar — Connection List */}
      <div className="sidebar">
        <div className="sidebar-header">
          <button className="back-btn" onClick={onBack}>
            &larr; Back
          </button>
          <h2>Connections ({capture.flows.length})</h2>
          <input
            className="search-box"
            type="text"
            placeholder="Filter connections or ask a question..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
        <div className="quick-filters">
          <button className="filter-pill">Slow</button>
          <button className="filter-pill">Errors</button>
          <button className="filter-pill">DNS</button>
          <button className="filter-pill">Retransmissions</button>
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

      {/* Center — Timeline */}
      <div className="main-panel">
        <div className="main-panel-header">
          <h2>
            {selectedFlow
              ? `${selectedFlow.srcIp} → ${selectedFlow.dstIp}`
              : "Select a connection"}
          </h2>
        </div>
        <div className="timeline">
          {selectedFlow ? (
            <Timeline events={selectedFlow.events} />
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
  return (
    <div
      className={`connection-item ${selected ? "selected" : ""}`}
      onClick={onClick}
    >
      <div className="connection-host">{flow.dstIp}</div>
      <div className="connection-meta">
        {flow.protocol} &middot; {flow.packetCount} pkts &middot; {flow.srcPort}{" "}
        → {flow.dstPort}
      </div>
    </div>
  );
}
