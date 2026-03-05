import type { Finding } from "../types";

interface Props {
  finding: Finding;
  onClose: () => void;
}

export function EvidenceDrawer({ finding, onClose }: Props) {
  const allFrames = finding.evidence.flatMap((e) => e.frameNumbers);

  return (
    <div className="evidence-drawer">
      <div className="evidence-drawer-header">
        Evidence: {finding.title}
        <button
          className="back-btn"
          style={{ float: "right" }}
          onClick={onClose}
        >
          Close
        </button>
      </div>
      <table className="packet-table">
        <thead>
          <tr>
            <th>Frame</th>
            <th>Field</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {finding.evidence.map((ev, i) =>
            ev.frameNumbers.map((frame) => (
              <tr
                key={`${i}-${frame}`}
                className={allFrames.includes(frame) ? "highlighted" : ""}
              >
                <td>{frame}</td>
                <td>{ev.label}</td>
                <td>{ev.value}</td>
              </tr>
            )),
          )}
        </tbody>
      </table>
    </div>
  );
}
