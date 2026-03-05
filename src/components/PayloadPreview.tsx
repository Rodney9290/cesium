import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface HttpEntry {
  frameNumber: string;
  time: string;
  srcIp: string;
  dstIp: string;
  method: string;
  uri: string;
  responseCode: string;
  contentType: string;
  contentLength: string;
  host: string;
  userAgent: string;
  server: string;
}

export function PayloadPreview() {
  const [entries, setEntries] = useState<HttpEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    invoke<string>("get_http_payloads")
      .then((raw) => {
        const lines = raw.trim().split("\n");
        if (lines.length < 2) { setEntries([]); return; }
        const parsed: HttpEntry[] = [];
        for (let i = 1; i < lines.length; i++) {
          const parts = lines[i].split("|");
          if (parts.length < 12) continue;
          parsed.push({
            frameNumber: parts[0],
            time: parts[1],
            srcIp: parts[2],
            dstIp: parts[3],
            method: parts[4],
            uri: parts[5],
            responseCode: parts[6],
            contentType: parts[7],
            contentLength: parts[8],
            host: parts[9],
            userAgent: parts[10],
            server: parts[11],
          });
        }
        setEntries(parsed);
      })
      .catch(() => setEntries([]))
      .finally(() => setLoading(false));
  }, []);

  const filtered = entries.filter((e) => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    return (
      e.uri.toLowerCase().includes(q) ||
      e.host.toLowerCase().includes(q) ||
      e.method.toLowerCase().includes(q) ||
      e.contentType.toLowerCase().includes(q)
    );
  });

  if (loading) return <p className="hex-loading">Loading HTTP data...</p>;
  if (entries.length === 0) return <p style={{ color: "var(--text-tertiary)", padding: 16 }}>No HTTP traffic found in this capture.</p>;

  const statusColor = (code: string) => {
    const c = parseInt(code);
    if (c >= 200 && c < 300) return "status-ok";
    if (c >= 300 && c < 400) return "status-redirect";
    if (c >= 400 && c < 500) return "status-client-err";
    if (c >= 500) return "status-server-err";
    return "";
  };

  return (
    <div className="payload-preview">
      <div className="payload-controls">
        <input
          className="search-box"
          placeholder="Filter by URL, host, method..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          style={{ margin: 0, maxWidth: 300 }}
        />
        <span className="dns-count">{filtered.length} HTTP transactions</span>
      </div>
      <div className="payload-list">
        {filtered.map((entry, i) => (
          <div key={i} className="payload-entry">
            <div className="payload-header">
              <span className="dns-frame">#{entry.frameNumber}</span>
              <span className="dns-time">{parseFloat(entry.time).toFixed(4)}s</span>
              {entry.method && (
                <span className={`http-method method-${entry.method.toLowerCase()}`}>{entry.method}</span>
              )}
              {entry.responseCode && (
                <span className={`http-status ${statusColor(entry.responseCode)}`}>{entry.responseCode}</span>
              )}
            </div>
            <div className="payload-detail">
              {entry.host && entry.uri && (
                <div className="payload-url">{entry.host}{entry.uri}</div>
              )}
              {entry.uri && !entry.host && (
                <div className="payload-url">{entry.uri}</div>
              )}
              <div className="payload-meta">
                {entry.contentType && <span>Type: {entry.contentType}</span>}
                {entry.contentLength && <span>Size: {entry.contentLength}B</span>}
                {entry.server && <span>Server: {entry.server}</span>}
                {entry.userAgent && <span className="payload-ua" title={entry.userAgent}>UA: {entry.userAgent.slice(0, 60)}{entry.userAgent.length > 60 ? "..." : ""}</span>}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
