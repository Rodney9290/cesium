import { useState, useEffect, useRef, useCallback } from "react";
import type { PacketSummary } from "../types";

interface Props {
  packets: PacketSummary[];
  srcIp: string;
}

export function FlowReplay({ packets, srcIp }: Props) {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const timerRef = useRef<number | null>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const stopPlayback = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    setPlaying(false);
  }, []);

  const scheduleNext = useCallback(() => {
    if (currentIndex >= packets.length - 1) {
      stopPlayback();
      return;
    }
    const delay = Math.max(
      10,
      ((packets[currentIndex + 1].relativeTime - packets[currentIndex].relativeTime) * 1000) / speed,
    );
    timerRef.current = window.setTimeout(() => {
      setCurrentIndex((prev) => {
        if (prev >= packets.length - 1) {
          stopPlayback();
          return prev;
        }
        return prev + 1;
      });
    }, Math.min(delay, 2000));
  }, [currentIndex, packets, speed, stopPlayback]);

  useEffect(() => {
    if (playing) scheduleNext();
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [playing, currentIndex, scheduleNext]);

  useEffect(() => {
    const el = listRef.current?.querySelector(`[data-idx="${currentIndex}"]`);
    el?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [currentIndex]);

  const progress = packets.length > 1 ? (currentIndex / (packets.length - 1)) * 100 : 0;

  return (
    <div className="flow-replay">
      <div className="replay-controls">
        <button className="btn-icon" onClick={() => { setCurrentIndex(0); stopPlayback(); }} title="Reset">|&lt;</button>
        <button className="btn-icon" onClick={() => setCurrentIndex(Math.max(0, currentIndex - 1))} title="Previous">&lt;</button>
        <button
          className={`btn-icon ${playing ? "active" : ""}`}
          onClick={() => playing ? stopPlayback() : setPlaying(true)}
        >
          {playing ? "Pause" : "Play"}
        </button>
        <button className="btn-icon" onClick={() => setCurrentIndex(Math.min(packets.length - 1, currentIndex + 1))} title="Next">&gt;</button>
        <span className="replay-counter">{currentIndex + 1} / {packets.length}</span>
        <select className="replay-speed" value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
          <option value={0.25}>0.25x</option>
          <option value={0.5}>0.5x</option>
          <option value={1}>1x</option>
          <option value={2}>2x</option>
          <option value={5}>5x</option>
          <option value={10}>10x</option>
          <option value={50}>50x</option>
        </select>
      </div>
      <div className="replay-progress">
        <div className="replay-bar" style={{ width: `${progress}%` }} />
      </div>
      <div className="replay-conversation" ref={listRef}>
        {packets.slice(0, currentIndex + 1).map((p, i) => {
          const fromSrc = p.srcIp === srcIp;
          return (
            <div
              key={i}
              data-idx={i}
              className={`replay-message ${fromSrc ? "outgoing" : "incoming"} ${i === currentIndex ? "current" : ""}`}
            >
              <div className="replay-msg-header">
                <span className={`replay-direction ${fromSrc ? "out" : "in"}`}>
                  {fromSrc ? ">>>" : "<<<"}
                </span>
                <span className="replay-time">+{p.relativeTime.toFixed(6)}s</span>
                <span className={`proto-badge ${p.protocol.toLowerCase()}`}>{p.protocol}</span>
                <span className="replay-len">{p.length} bytes</span>
              </div>
              <div className="replay-msg-info">{p.info}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
