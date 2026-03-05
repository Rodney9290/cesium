import { useState, useMemo, useRef, useEffect } from "react";
import type { PacketSummary } from "../types";

interface Props {
  packets: PacketSummary[];
}

const PAGE_SIZE = 100;

export function PacketTable({ packets }: Props) {
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);
  const scrollRef = useRef<HTMLDivElement>(null);

  const visible = useMemo(
    () => packets.slice(0, visibleCount),
    [packets, visibleCount],
  );

  useEffect(() => {
    setVisibleCount(PAGE_SIZE);
  }, [packets]);

  const handleScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 100) {
      setVisibleCount((prev) => Math.min(prev + PAGE_SIZE, packets.length));
    }
  };

  if (packets.length === 0) {
    return (
      <p style={{ color: "var(--text-tertiary)", padding: 24 }}>
        No packets in this flow.
      </p>
    );
  }

  return (
    <div
      className="packet-table-wrap"
      ref={scrollRef}
      onScroll={handleScroll}
    >
      <table className="packet-table full-width">
        <thead>
          <tr>
            <th>#</th>
            <th>Time</th>
            <th>Delta</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Protocol</th>
            <th>Length</th>
            <th>Info</th>
          </tr>
        </thead>
        <tbody>
          {visible.map((pkt) => (
            <tr key={pkt.frameNumber}>
              <td>{pkt.frameNumber}</td>
              <td>{pkt.relativeTime.toFixed(6)}</td>
              <td>{pkt.deltaTime > 0 ? pkt.deltaTime.toFixed(6) : "—"}</td>
              <td>
                {pkt.srcIp}
                {pkt.srcPort != null ? `:${pkt.srcPort}` : ""}
              </td>
              <td>
                {pkt.dstIp}
                {pkt.dstPort != null ? `:${pkt.dstPort}` : ""}
              </td>
              <td>
                <span className={`proto-badge ${pkt.protocol.toLowerCase()}`}>
                  {pkt.protocol}
                </span>
              </td>
              <td>{pkt.length}</td>
              <td className="info-cell">{pkt.info}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {visibleCount < packets.length && (
        <div className="load-more">
          Showing {visibleCount} of {packets.length} packets
        </div>
      )}
    </div>
  );
}
