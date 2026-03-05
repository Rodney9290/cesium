import { useState, useEffect, useCallback } from "react";
import { HomeScreen } from "./components/HomeScreen";
import { CaptureView } from "./components/CaptureView";
import type { CaptureOverview } from "./types";

const RECENT_FILES_KEY = "cesium-recent-files";
const MAX_RECENT = 10;

export interface RecentFile {
  path: string;
  name: string;
  openedAt: number;
}

function loadRecentFiles(): RecentFile[] {
  try {
    return JSON.parse(localStorage.getItem(RECENT_FILES_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveRecentFile(path: string, name: string) {
  const recent = loadRecentFiles().filter((r) => r.path !== path);
  recent.unshift({ path, name, openedAt: Date.now() });
  localStorage.setItem(
    RECENT_FILES_KEY,
    JSON.stringify(recent.slice(0, MAX_RECENT)),
  );
}

function App() {
  const [capture, setCapture] = useState<CaptureOverview | null>(null);
  const [theme, setTheme] = useState<"light" | "dark" | "system">("system");
  const [recentFiles, setRecentFiles] = useState<RecentFile[]>(loadRecentFiles);

  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") {
      root.removeAttribute("data-theme");
    } else {
      root.setAttribute("data-theme", theme);
    }
  }, [theme]);

  const handleFileLoaded = useCallback(
    (cap: CaptureOverview, path?: string) => {
      setCapture(cap);
      if (path) {
        saveRecentFile(path, cap.filename);
        setRecentFiles(loadRecentFiles());
      }
    },
    [],
  );

  const cycleTheme = () => {
    setTheme((prev) => {
      if (prev === "system") return "light";
      if (prev === "light") return "dark";
      return "system";
    });
  };

  const themeLabel =
    theme === "system" ? "Auto" : theme === "light" ? "Light" : "Dark";

  return (
    <div className="app">
      <button
        className="theme-toggle"
        onClick={cycleTheme}
        title={`Theme: ${themeLabel}`}
      >
        {theme === "dark" ? "🌙" : theme === "light" ? "☀️" : "🖥️"}
      </button>
      {capture ? (
        <CaptureView capture={capture} onBack={() => setCapture(null)} />
      ) : (
        <HomeScreen
          onFileLoaded={handleFileLoaded}
          recentFiles={recentFiles}
        />
      )}
    </div>
  );
}

export default App;
