import { useState, useEffect } from "react";
import { HomeScreen } from "./components/HomeScreen";
import { CaptureView } from "./components/CaptureView";
import type { CaptureOverview } from "./types";

function App() {
  const [capture, setCapture] = useState<CaptureOverview | null>(null);
  const [theme, setTheme] = useState<"light" | "dark" | "system">("system");

  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") {
      root.removeAttribute("data-theme");
    } else {
      root.setAttribute("data-theme", theme);
    }
  }, [theme]);

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
        <HomeScreen onFileLoaded={setCapture} />
      )}
    </div>
  );
}

export default App;
