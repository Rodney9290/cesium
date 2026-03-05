import { useState } from "react";
import { HomeScreen } from "./components/HomeScreen";
import { CaptureView } from "./components/CaptureView";
import type { CaptureOverview } from "./types";

function App() {
  const [capture, setCapture] = useState<CaptureOverview | null>(null);

  return (
    <div className="app">
      {capture ? (
        <CaptureView capture={capture} onBack={() => setCapture(null)} />
      ) : (
        <HomeScreen onFileLoaded={setCapture} />
      )}
    </div>
  );
}

export default App;
