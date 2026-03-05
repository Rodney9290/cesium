import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface DnsEntry {
  frameNumber: string;
  time: string;
  srcIp: string;
  dstIp: string;
  queryName: string;
  queryType: string;
  isResponse: boolean;
  answer: string;
  rcode: string;
  responseTime: string;
}

export function DnsTimeline() {
  const [entries, setEntries] = useState<DnsEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const [showOnlyErrors, setShowOnlyErrors] = useState(false);

  useEffect(() => {
    invoke<string>("get_dns_timeline")
      .then((raw) => {
        const lines = raw.trim().split("\n");
        if (lines.length < 2) { setEntries([]); return; }
        const parsed: DnsEntry[] = [];
        for (let i = 1; i < lines.length; i++) {
          const parts = lines[i].split("|");
          if (parts.length < 12) continue;
          parsed.push({
            frameNumber: parts[0],
            time: parts[1],
            srcIp: parts[2],
            dstIp: parts[3],
            queryName: parts[4],
            queryType: parts[5],
            isResponse: parts[6] === "1" || parts[6] === "true",
            answer: [parts[7], parts[8], parts[9]].filter(Boolean).join(", "),
            rcode: parts[10],
            responseTime: parts[11],
          });
        }
        setEntries(parsed);
      })
      .catch(() => setEntries([]))
      .finally(() => setLoading(false));
  }, []);

  const filtered = entries.filter((e) => {
    if (showOnlyErrors && e.rcode !== "0" && e.rcode !== "" && e.isResponse) return true;
    if (showOnlyErrors && !(e.rcode !== "0" && e.rcode !== "" && e.isResponse)) return false;
    if (filter && !e.queryName.toLowerCase().includes(filter.toLowerCase())) return false;
    return true;
  });

  // Pair queries with responses
  const pairs: { query: DnsEntry; response?: DnsEntry }[] = [];
  const responseMap = new Map<string, DnsEntry>();
  for (const e of filtered) {
    if (e.isResponse) {
      responseMap.set(e.queryName + e.queryType, e);
    }
  }
  for (const e of filtered) {
    if (!e.isResponse) {
      pairs.push({ query: e, response: responseMap.get(e.queryName + e.queryType) });
    }
  }

  if (loading) return <p className="hex-loading">Loading DNS data...</p>;

  const rcodeLabel = (code: string) => {
    const map: Record<string, string> = { "0": "OK", "1": "Format Error", "2": "Server Fail", "3": "NXDOMAIN", "5": "Refused" };
    return map[code] || code;
  };

  return (
    <div className="dns-timeline">
      <div className="dns-controls">
        <input
          className="search-box"
          placeholder="Filter by domain..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          style={{ margin: 0, maxWidth: 300 }}
        />
        <label className="dns-error-toggle">
          <input type="checkbox" checked={showOnlyErrors} onChange={(e) => setShowOnlyErrors(e.target.checked)} />
          Errors only
        </label>
        <span className="dns-count">{pairs.length} queries</span>
      </div>
      <div className="dns-list">
        {pairs.length === 0 ? (
          <p style={{ color: "var(--text-tertiary)", padding: 16 }}>No DNS queries found.</p>
        ) : (
          pairs.map((pair, i) => {
            const hasError = pair.response && pair.response.rcode !== "0" && pair.response.rcode !== "";
            const latency = pair.response?.responseTime ? parseFloat(pair.response.responseTime) * 1000 : null;
            return (
              <div key={i} className={`dns-entry ${hasError ? "dns-error" : ""}`}>
                <div className="dns-query-line">
                  <span className="dns-frame">#{pair.query.frameNumber}</span>
                  <span className="dns-time">{parseFloat(pair.query.time).toFixed(4)}s</span>
                  <span className="dns-name">{pair.query.queryName || "(empty)"}</span>
                  <span className="dns-type">{pair.query.queryType}</span>
                </div>
                {pair.response && (
                  <div className="dns-response-line">
                    <span className={`dns-rcode ${hasError ? "error" : "ok"}`}>
                      {rcodeLabel(pair.response.rcode)}
                    </span>
                    {pair.response.answer && (
                      <span className="dns-answer">{pair.response.answer}</span>
                    )}
                    {latency != null && (
                      <span className={`dns-latency ${latency > 100 ? "slow" : ""}`}>
                        {latency.toFixed(1)}ms
                      </span>
                    )}
                  </div>
                )}
                {!pair.response && (
                  <div className="dns-response-line">
                    <span className="dns-rcode error">No response</span>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
