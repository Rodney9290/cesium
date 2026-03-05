import { useState, useCallback, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import type { CaptureOverview } from "../types";

interface Props {
  onFileLoaded: (capture: CaptureOverview) => void;
}

export function HomeScreen({ onFileLoaded }: Props) {
  const [dragActive, setDragActive] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadFile = useCallback(
    async (path: string) => {
      setLoading(true);
      setError(null);
      try {
        const result = await invoke<CaptureOverview>("open_pcap", { path });
        onFileLoaded(result);
      } catch (e) {
        setError(String(e));
      } finally {
        setLoading(false);
      }
    },
    [onFileLoaded],
  );

  // Listen for Tauri file drop events
  useEffect(() => {
    let unlisten: (() => void) | undefined;

    getCurrentWebviewWindow()
      .onDragDropEvent((event) => {
        if (event.payload.type === "over") {
          setDragActive(true);
        } else if (event.payload.type === "drop") {
          setDragActive(false);
          const paths = event.payload.paths;
          if (paths.length > 0) {
            loadFile(paths[0]);
          }
        } else {
          setDragActive(false);
        }
      })
      .then((fn) => {
        unlisten = fn;
      });

    return () => {
      unlisten?.();
    };
  }, [loadFile]);

  const handleClick = async () => {
    const selected = await open({
      multiple: false,
      filters: [
        {
          name: "Packet Capture",
          extensions: ["pcap", "pcapng", "cap"],
        },
      ],
    });
    if (selected) {
      await loadFile(selected);
    }
  };

  return (
    <div className="home">
      <h1>Cesium</h1>
      <p>
        Open a packet capture to see connection timelines, diagnostics, and
        explainable analysis — no Wireshark expertise required.
      </p>

      <div
        className={`drop-zone ${dragActive ? "active" : ""}`}
        onClick={handleClick}
      >
        {loading ? (
          <span className="drop-zone-label">Analyzing capture...</span>
        ) : (
          <>
            <span className="drop-zone-label">
              Drop a .pcap or .pcapng file here
            </span>
            <span className="drop-zone-hint">or click to browse</span>
          </>
        )}
      </div>

      {error && (
        <p style={{ color: "var(--error)", fontSize: 14 }}>{error}</p>
      )}

      <p className="privacy-note">
        Your capture files are processed locally. Cesium never uploads packet
        data anywhere.
      </p>
    </div>
  );
}
