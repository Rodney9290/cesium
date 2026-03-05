import { useState, useCallback, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import type { CaptureOverview } from "../types";
import type { RecentFile } from "../App";

interface Props {
  onFileLoaded: (capture: CaptureOverview, path?: string) => void;
  recentFiles: RecentFile[];
}

export function HomeScreen({ onFileLoaded, recentFiles }: Props) {
  const [dragActive, setDragActive] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [capturing, setCapturing] = useState(false);
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [selectedInterface, setSelectedInterface] = useState("");
  const [showCapture, setShowCapture] = useState(false);

  const loadFile = useCallback(
    async (path: string) => {
      setLoading(true);
      setError(null);
      try {
        const result = await invoke<CaptureOverview>("open_pcap", { path });
        onFileLoaded(result, path);
      } catch (e) {
        setError(String(e));
      } finally {
        setLoading(false);
      }
    },
    [onFileLoaded],
  );

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

  const handleStartCapture = async () => {
    if (!selectedInterface) return;
    setCapturing(true);
    setError(null);
    try {
      // Extract just the interface name (before any parenthetical description)
      const ifName = selectedInterface.split(" ")[0];
      await invoke<string>("start_capture", { interface: ifName });
    } catch (e) {
      setError(String(e));
      setCapturing(false);
    }
  };

  const handleStopCapture = async () => {
    try {
      const outputPath = await invoke<string>("stop_capture");
      setCapturing(false);
      await loadFile(outputPath);
    } catch (e) {
      setError(String(e));
      setCapturing(false);
    }
  };

  const handleShowCapture = async () => {
    setShowCapture(true);
    try {
      const ifaces = await invoke<string[]>("list_interfaces");
      setInterfaces(ifaces);
      if (ifaces.length > 0) setSelectedInterface(ifaces[0]);
    } catch (e) {
      setError(String(e));
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

      {!showCapture && !capturing && (
        <button className="btn btn-secondary" onClick={handleShowCapture}>
          Or start a live capture
        </button>
      )}

      {showCapture && !capturing && (
        <div className="live-capture-controls">
          <select
            className="search-box"
            value={selectedInterface}
            onChange={(e) => setSelectedInterface(e.target.value)}
          >
            {interfaces.map((iface) => (
              <option key={iface} value={iface}>
                {iface}
              </option>
            ))}
          </select>
          <button className="btn btn-primary" onClick={handleStartCapture}>
            Start Capture
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => setShowCapture(false)}
          >
            Cancel
          </button>
        </div>
      )}

      {capturing && (
        <div className="live-capture-controls">
          <span className="capture-indicator">Recording...</span>
          <button className="btn btn-primary" onClick={handleStopCapture}>
            Stop & Analyze
          </button>
        </div>
      )}

      {error && (
        <p style={{ color: "var(--error)", fontSize: 14 }}>{error}</p>
      )}

      {recentFiles.length > 0 && (
        <div className="recent-files">
          <h3>Recent Files</h3>
          <ul>
            {recentFiles.map((rf) => (
              <li key={rf.path} onClick={() => loadFile(rf.path)}>
                <span className="recent-name">{rf.name}</span>
                <span className="recent-date">
                  {new Date(rf.openedAt).toLocaleDateString()}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <p className="privacy-note">
        Your capture files are processed locally. Cesium never uploads packet
        data anywhere.
      </p>
    </div>
  );
}
