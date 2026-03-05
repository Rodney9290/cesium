import type { Finding } from "../types";

interface Props {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
}

export function FindingsPanel({ findings, onSelectFinding }: Props) {
  return (
    <div className="findings-panel">
      <div className="findings-header">
        <h2>Diagnostics ({findings.length})</h2>
      </div>
      <div className="findings-list">
        {findings.length === 0 ? (
          <p
            style={{
              color: "var(--text-tertiary)",
              fontSize: 13,
              padding: 16,
            }}
          >
            No issues detected for this connection.
          </p>
        ) : (
          findings.map((finding) => (
            <div
              className="finding-card"
              key={finding.id}
              onClick={() => onSelectFinding(finding)}
            >
              <div>
                <span className={`finding-severity ${finding.severity}`} />
                <span className="finding-title">{finding.title}</span>
              </div>
              <div className="finding-explanation">{finding.explanation}</div>
              {finding.evidence.length > 0 && (
                <div className="finding-evidence">
                  {finding.evidence.map((e, i) => (
                    <div key={i}>
                      {e.label}: {e.value} (frames:{" "}
                      {e.frameNumbers.join(", ")})
                    </div>
                  ))}
                </div>
              )}
              {finding.caveat && (
                <div className="finding-caveat">{finding.caveat}</div>
              )}
              <div className="finding-confidence">
                Confidence: {finding.confidence}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
