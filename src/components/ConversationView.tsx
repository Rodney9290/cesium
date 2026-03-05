import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Flow } from "../types";

interface Props {
  flow: Flow;
}

interface StreamSegment {
  direction: "client" | "server";
  data: string;
}

function parseFollowOutput(raw: string): StreamSegment[] {
  const segments: StreamSegment[] = [];
  const lines = raw.split("\n");
  let inStream = false;
  let currentDirection: "client" | "server" = "client";
  let currentData: string[] = [];

  for (const line of lines) {
    if (line.startsWith("===================================================================")) {
      if (inStream && currentData.length > 0) {
        segments.push({ direction: currentDirection, data: currentData.join("\n") });
        currentData = [];
      }
      inStream = true;
      continue;
    }

    if (!inStream) continue;

    // Node markers in tshark follow output
    if (line.match(/^\t/)) {
      if (currentData.length > 0) {
        segments.push({ direction: currentDirection, data: currentData.join("\n") });
        currentData = [];
      }
      currentDirection = "server";
      currentData.push(line.replace(/^\t/, ""));
    } else if (line.trim() !== "") {
      if (currentDirection === "server" && currentData.length > 0) {
        segments.push({ direction: currentDirection, data: currentData.join("\n") });
        currentData = [];
        currentDirection = "client";
      }
      currentData.push(line);
    }
  }

  if (currentData.length > 0) {
    segments.push({ direction: currentDirection, data: currentData.join("\n") });
  }

  // If parsing didn't produce segments, show raw output as a single block
  if (segments.length === 0 && raw.trim().length > 0) {
    // Split by indented (server) vs non-indented (client) sections
    let current: string[] = [];
    let dir: "client" | "server" = "client";
    for (const line of lines) {
      if (line.startsWith("\t")) {
        if (dir === "client" && current.length > 0) {
          segments.push({ direction: "client", data: current.join("\n") });
          current = [];
        }
        dir = "server";
        current.push(line.replace(/^\t/, ""));
      } else if (line.trim()) {
        if (dir === "server" && current.length > 0) {
          segments.push({ direction: "server", data: current.join("\n") });
          current = [];
        }
        dir = "client";
        current.push(line);
      }
    }
    if (current.length > 0) {
      segments.push({ direction: dir, data: current.join("\n") });
    }
  }

  return segments;
}

export function ConversationView({ flow }: Props) {
  const [segments, setSegments] = useState<StreamSegment[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rawMode, setRawMode] = useState(false);
  const [rawData, setRawData] = useState("");

  useEffect(() => {
    setLoading(true);
    setError(null);
    invoke<string>("get_stream_data", {
      srcIp: flow.srcIp,
      srcPort: flow.srcPort,
      dstIp: flow.dstIp,
      dstPort: flow.dstPort,
    })
      .then((raw) => {
        setRawData(raw);
        setSegments(parseFollowOutput(raw));
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [flow.srcIp, flow.srcPort, flow.dstIp, flow.dstPort]);

  if (loading) return <p className="hex-loading">Following TCP stream...</p>;
  if (error) return <p style={{ color: "var(--text-tertiary)", padding: 16 }}>{error}</p>;

  return (
    <div className="conversation-view">
      <div className="conv-header">
        <div className="conv-parties">
          <span className="conv-client">{flow.srcIp}:{flow.srcPort}</span>
          <span className="conv-arrow"> &lt;--&gt; </span>
          <span className="conv-server">{flow.dstIp}:{flow.dstPort}</span>
        </div>
        <button className="btn-icon" onClick={() => setRawMode(!rawMode)}>
          {rawMode ? "Parsed" : "Raw"}
        </button>
      </div>
      {rawMode ? (
        <div className="hex-content">{rawData}</div>
      ) : segments.length > 0 ? (
        <div className="conv-messages">
          {segments.map((seg, i) => (
            <div key={i} className={`conv-segment ${seg.direction}`}>
              <div className="conv-seg-label">
                {seg.direction === "client" ? "Client" : "Server"}
              </div>
              <pre className="conv-seg-data">{seg.data.slice(0, 5000)}{seg.data.length > 5000 ? "\n... (truncated)" : ""}</pre>
            </div>
          ))}
        </div>
      ) : (
        <p style={{ color: "var(--text-tertiary)", padding: 16 }}>No stream data available for this flow. This may be a non-TCP flow.</p>
      )}
    </div>
  );
}
