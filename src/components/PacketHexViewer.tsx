import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface Props {
  frameNumber: number;
}

export function PacketHexViewer({ frameNumber }: Props) {
  const [hex, setHex] = useState<string | null>(null);
  const [details, setDetails] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<"hex" | "decoded">("decoded");

  const load = async () => {
    if (hex !== null) return;
    setLoading(true);
    try {
      const [h, d] = await Promise.all([
        invoke<string>("get_packet_hex", { frameNumber }),
        invoke<string>("get_packet_details", { frameNumber }),
      ]);
      setHex(h);
      setDetails(d);
    } catch {
      setHex("Failed to load hex data");
      setDetails("Failed to load packet details");
    }
    setLoading(false);
  };

  if (hex === null && !loading) {
    return (
      <button className="btn-icon" onClick={load}>
        Inspect Frame #{frameNumber}
      </button>
    );
  }

  if (loading) {
    return <span className="hex-loading">Loading frame #{frameNumber}...</span>;
  }

  return (
    <div className="hex-viewer">
      <div className="hex-tabs">
        <button
          className={`tab-btn ${tab === "decoded" ? "active" : ""}`}
          onClick={() => setTab("decoded")}
        >
          Protocol Details
        </button>
        <button
          className={`tab-btn ${tab === "hex" ? "active" : ""}`}
          onClick={() => setTab("hex")}
        >
          Hex Dump
        </button>
      </div>
      <pre className="hex-content">
        {tab === "hex" ? hex : details}
      </pre>
    </div>
  );
}
