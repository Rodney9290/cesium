import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface TlsCert {
  frameNumber: string;
  srcIp: string;
  dstIp: string;
  dnsNames: string;
  validity: string;
  subject: string;
  cipherSuite: string;
  version: string;
}

export function TlsInspector() {
  const [certs, setCerts] = useState<TlsCert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    invoke<string>("get_tls_info")
      .then((raw) => {
        const lines = raw.trim().split("\n");
        if (lines.length < 2) { setCerts([]); return; }
        const parsed: TlsCert[] = [];
        for (let i = 1; i < lines.length; i++) {
          const parts = lines[i].split("|");
          if (parts.length < 8) continue;
          parsed.push({
            frameNumber: parts[0],
            srcIp: parts[1],
            dstIp: parts[2],
            dnsNames: parts[3],
            validity: parts[4],
            subject: parts[5],
            cipherSuite: parts[6],
            version: parts[7],
          });
        }
        setCerts(parsed);
      })
      .catch(() => setCerts([]))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <p className="hex-loading">Loading TLS data...</p>;
  if (certs.length === 0) return <p style={{ color: "var(--text-tertiary)", padding: 16 }}>No TLS certificates found in this capture.</p>;

  const versionLabel = (v: string) => {
    const map: Record<string, string> = {
      "0x0301": "TLS 1.0", "0x0302": "TLS 1.1", "0x0303": "TLS 1.2", "0x0304": "TLS 1.3",
      "769": "TLS 1.0", "770": "TLS 1.1", "771": "TLS 1.2", "772": "TLS 1.3",
    };
    return map[v] || v;
  };

  return (
    <div className="tls-inspector">
      <div className="tls-count">{certs.length} TLS certificate exchange{certs.length !== 1 ? "s" : ""}</div>
      <div className="tls-list">
        {certs.map((cert, i) => (
          <div key={i} className="tls-card">
            <div className="tls-header">
              <span className="tls-frame">Frame #{cert.frameNumber}</span>
              <span className="tls-version">{versionLabel(cert.version)}</span>
            </div>
            <div className="tls-detail">
              <div className="tls-row">
                <span className="tls-label">Server</span>
                <span className="tls-value">{cert.srcIp}</span>
              </div>
              {cert.dnsNames && (
                <div className="tls-row">
                  <span className="tls-label">DNS Names</span>
                  <span className="tls-value tls-names">{cert.dnsNames.split(",").join(", ")}</span>
                </div>
              )}
              {cert.subject && (
                <div className="tls-row">
                  <span className="tls-label">Subject</span>
                  <span className="tls-value">{cert.subject}</span>
                </div>
              )}
              {cert.validity && (
                <div className="tls-row">
                  <span className="tls-label">Validity</span>
                  <span className="tls-value">{cert.validity}</span>
                </div>
              )}
              {cert.cipherSuite && (
                <div className="tls-row">
                  <span className="tls-label">Cipher Suite</span>
                  <span className="tls-value tls-cipher">{cert.cipherSuite}</span>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
