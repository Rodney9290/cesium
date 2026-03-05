import { useState, useEffect, useCallback } from "react";
import { HomeScreen } from "./components/HomeScreen";
import { CaptureView } from "./components/CaptureView";
import type { CaptureOverview } from "./types";

const RECENT_FILES_KEY = "cesium-recent-files";
const SEARCH_HISTORY_KEY = "cesium-search-history";
const BOOKMARKS_KEY = "cesium-bookmarks";
const MAX_RECENT = 10;
const MAX_SEARCH_HISTORY = 20;

export interface RecentFile {
  path: string;
  name: string;
  openedAt: number;
}

export interface Bookmark {
  flowId: string;
  label: string;
  createdAt: number;
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

export function loadSearchHistory(): string[] {
  try {
    return JSON.parse(localStorage.getItem(SEARCH_HISTORY_KEY) || "[]");
  } catch {
    return [];
  }
}

export function saveSearchQuery(query: string) {
  if (!query.trim()) return;
  const history = loadSearchHistory().filter((q) => q !== query);
  history.unshift(query);
  localStorage.setItem(
    SEARCH_HISTORY_KEY,
    JSON.stringify(history.slice(0, MAX_SEARCH_HISTORY)),
  );
}

export function loadBookmarks(): Bookmark[] {
  try {
    return JSON.parse(localStorage.getItem(BOOKMARKS_KEY) || "[]");
  } catch {
    return [];
  }
}

export function saveBookmarks(bookmarks: Bookmark[]) {
  localStorage.setItem(BOOKMARKS_KEY, JSON.stringify(bookmarks));
}

function App() {
  const [captures, setCaptures] = useState<CaptureOverview[]>([]);
  const [activeIndex, setActiveIndex] = useState(0);
  const [theme, setTheme] = useState<"light" | "dark" | "system">("system");
  const [recentFiles, setRecentFiles] = useState<RecentFile[]>(loadRecentFiles);
  const [bookmarks, setBookmarks] = useState<Bookmark[]>(loadBookmarks);

  const capture = captures[activeIndex] ?? null;

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
      setCaptures((prev) => {
        const next = [...prev, cap];
        setActiveIndex(next.length - 1);
        return next;
      });
      if (path) {
        saveRecentFile(path, cap.filename);
        setRecentFiles(loadRecentFiles());
      }
    },
    [],
  );

  const handleBack = () => {
    setCaptures((prev) => prev.filter((_, i) => i !== activeIndex));
    setActiveIndex(0);
  };

  const toggleBookmark = useCallback((flowId: string, label: string) => {
    setBookmarks((prev) => {
      const exists = prev.find((b) => b.flowId === flowId);
      const next = exists
        ? prev.filter((b) => b.flowId !== flowId)
        : [...prev, { flowId, label, createdAt: Date.now() }];
      saveBookmarks(next);
      return next;
    });
  }, []);

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
        <>
          {captures.length > 1 && (
            <div className="capture-tabs">
              {captures.map((c, i) => (
                <button
                  key={i}
                  className={`capture-tab ${i === activeIndex ? "active" : ""}`}
                  onClick={() => setActiveIndex(i)}
                >
                  {c.filename}
                </button>
              ))}
            </div>
          )}
          <CaptureView
            capture={capture}
            onBack={handleBack}
            bookmarks={bookmarks}
            onToggleBookmark={toggleBookmark}
          />
        </>
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
