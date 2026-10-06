import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  InvestigationTimelineItem,
  TimelineFilterParams,
  TimelineReplaySession,
  TimelineContextResponse,
  TimelineSourceLayer,
  EpistemicStatus,
  CollectionStatus,
} from "../types/investigation";
import {
  fetchUnifiedTimeline,
  fetchTimelineReplay,
  fetchTimelineContext,
  bookmarkTimelineItem,
  removeTimelineBookmark,
  exportUnifiedTimeline,
} from "../lib/api";
import { RefreshIcon, SearchIcon, ExportIcon, FilterIcon } from "../components/Icons";

interface InvestigationUnifiedTimelineProps {
  caseId: number;
  onSelectEntityKey?: (entityKey: string) => void;
  onSelectAlertId?: (alertId: number) => void;
  onSelectEventId?: (eventId: string) => void;
}

export function InvestigationUnifiedTimeline({
  caseId,
  onSelectEntityKey,
  onSelectAlertId,
  onSelectEventId,
}: InvestigationUnifiedTimelineProps) {
  // Timeline Items & Replay Session State
  const [items, setItems] = useState<InvestigationTimelineItem[]>([]);
  const [replaySession, setReplaySession] = useState<TimelineReplaySession | null>(null);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [deterministicHash, setDeterministicHash] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Replay Controller State (Transient UI State only)
  const [currentFrameIndex, setCurrentFrameIndex] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1.0);
  const playTimerRef = useRef<number | null>(null);

  // Inspector / Context State
  const [selectedItem, setSelectedItem] = useState<InvestigationTimelineItem | null>(null);
  const [itemContext, setItemContext] = useState<TimelineContextResponse | null>(null);
  const [contextLoading, setContextLoading] = useState<boolean>(false);
  const [bookmarking, setBookmarking] = useState<boolean>(false);
  const [bookmarkNote, setBookmarkNote] = useState<string>("");

  // Filters State
  const [filterHost, setFilterHost] = useState<string>("");
  const [filterEventType, setFilterEventType] = useState<string>("");
  const [filterLayer, setFilterLayer] = useState<TimelineSourceLayer | "">("");
  const [filterEpistemic, setFilterEpistemic] = useState<EpistemicStatus | "">("");
  const [filterCollection, setFilterCollection] = useState<CollectionStatus | "">("");
  const [filterSearch, setFilterSearch] = useState<string>("");
  const [filterStartTime, setFilterStartTime] = useState<string>("");
  const [filterEndTime, setFilterEndTime] = useState<string>("");

  // Notification Banner
  const [notice, setNotice] = useState<string | null>(null);

  // Load Timeline & Replay
  const loadTimelineData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: TimelineFilterParams = {
        limit: 500,
        offset: 0,
      };
      if (filterHost) params.host = filterHost.trim();
      if (filterEventType) params.event_type = filterEventType.trim();
      if (filterLayer) params.source_layer = filterLayer;
      if (filterEpistemic) params.epistemic_status = filterEpistemic;
      if (filterCollection) params.collection_status = filterCollection;
      if (filterSearch) params.search_text = filterSearch.trim();
      if (filterStartTime) params.start_time = filterStartTime.trim();
      if (filterEndTime) params.end_time = filterEndTime.trim();

      const [timelineRes, replayRes] = await Promise.all([
        fetchUnifiedTimeline(caseId, params),
        fetchTimelineReplay(caseId, params),
      ]);

      setItems(timelineRes.items);
      setTotalCount(timelineRes.total);
      setDeterministicHash(timelineRes.deterministic_hash);
      setReplaySession(replayRes);
      setCurrentFrameIndex(0);

      if (timelineRes.items.length > 0) {
        setSelectedItem(timelineRes.items[0]);
      } else {
        setSelectedItem(null);
        setItemContext(null);
      }
    } catch (err: any) {
      setError(`Failed to load investigation timeline: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, [caseId, filterHost, filterEventType, filterLayer, filterEpistemic, filterCollection, filterSearch, filterStartTime, filterEndTime]);

  useEffect(() => {
    loadTimelineData();
  }, [loadTimelineData]);

  // Load Context on Item Selection
  useEffect(() => {
    if (!selectedItem) {
      setItemContext(null);
      return;
    }
    let isCancelled = false;
    setContextLoading(true);
    fetchTimelineContext(caseId, selectedItem.timeline_id)
      .then((res) => {
        if (!isCancelled) {
          setItemContext(res);
        }
      })
      .catch(() => {
        if (!isCancelled) {
          setItemContext(null);
        }
      })
      .finally(() => {
        if (!isCancelled) {
          setContextLoading(false);
        }
      });
    return () => {
      isCancelled = true;
    };
  }, [caseId, selectedItem]);

  // Replay Animation Loop
  useEffect(() => {
    if (!isPlaying || !replaySession || replaySession.frames.length <= 1) {
      if (playTimerRef.current !== null) {
        window.clearTimeout(playTimerRef.current);
        playTimerRef.current = null;
      }
      return;
    }

    const intervalMs = Math.max(250, Math.floor(1000 / playbackSpeed));
    playTimerRef.current = window.setTimeout(() => {
      setCurrentFrameIndex((prevIndex) => {
        if (prevIndex >= replaySession.frames.length - 1) {
          setIsPlaying(false);
          return prevIndex;
        }
        const nextIndex = prevIndex + 1;
        const frame = replaySession.frames[nextIndex];
        if (frame) {
          setSelectedItem(frame.item);
        }
        return nextIndex;
      });
    }, intervalMs);

    return () => {
      if (playTimerRef.current !== null) {
        window.clearTimeout(playTimerRef.current);
        playTimerRef.current = null;
      }
    };
  }, [isPlaying, currentFrameIndex, playbackSpeed, replaySession]);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return;
      }
      if (e.code === "Space") {
        e.preventDefault();
        setIsPlaying((p) => !p);
      } else if (e.code === "ArrowRight") {
        e.preventDefault();
        stepForward();
      } else if (e.code === "ArrowLeft") {
        e.preventDefault();
        stepBackward();
      } else if (e.code === "Home") {
        e.preventDefault();
        jumpToStart();
      } else if (e.code === "End") {
        e.preventDefault();
        jumpToEnd();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [replaySession, currentFrameIndex]);

  // Navigation handlers
  const stepForward = () => {
    if (!replaySession || replaySession.frames.length === 0) return;
    const nextIdx = Math.min(currentFrameIndex + 1, replaySession.frames.length - 1);
    setCurrentFrameIndex(nextIdx);
    setSelectedItem(replaySession.frames[nextIdx].item);
  };

  const stepBackward = () => {
    if (!replaySession || replaySession.frames.length === 0) return;
    const prevIdx = Math.max(currentFrameIndex - 1, 0);
    setCurrentFrameIndex(prevIdx);
    setSelectedItem(replaySession.frames[prevIdx].item);
  };

  const jumpToStart = () => {
    if (!replaySession || replaySession.frames.length === 0) return;
    setCurrentFrameIndex(0);
    setSelectedItem(replaySession.frames[0].item);
  };

  const jumpToEnd = () => {
    if (!replaySession || replaySession.frames.length === 0) return;
    const lastIdx = replaySession.frames.length - 1;
    setCurrentFrameIndex(lastIdx);
    setSelectedItem(replaySession.frames[lastIdx].item);
  };

  const jumpToNextEvidence = () => {
    if (!replaySession) return;
    for (let i = currentFrameIndex + 1; i < replaySession.frames.length; i++) {
      if (replaySession.frames[i].item.source_layer === "EVIDENCE" || replaySession.frames[i].item.evidence_refs.length > 0) {
        setCurrentFrameIndex(i);
        setSelectedItem(replaySession.frames[i].item);
        return;
      }
    }
    setNotice("No subsequent evidence items found");
    setTimeout(() => setNotice(null), 3000);
  };

  const jumpToPrevEvidence = () => {
    if (!replaySession) return;
    for (let i = currentFrameIndex - 1; i >= 0; i--) {
      if (replaySession.frames[i].item.source_layer === "EVIDENCE" || replaySession.frames[i].item.evidence_refs.length > 0) {
        setCurrentFrameIndex(i);
        setSelectedItem(replaySession.frames[i].item);
        return;
      }
    }
    setNotice("No preceding evidence items found");
    setTimeout(() => setNotice(null), 3000);
  };

  const handleScrubberChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = parseInt(e.target.value, 10);
    if (!isNaN(val) && replaySession && replaySession.frames[val]) {
      setCurrentFrameIndex(val);
      setSelectedItem(replaySession.frames[val].item);
    }
  };

  const handleToggleBookmark = async () => {
    if (!selectedItem) return;
    setBookmarking(true);
    try {
      if (selectedItem.is_bookmarked) {
        await removeTimelineBookmark(caseId, selectedItem.timeline_id);
        setSelectedItem({ ...selectedItem, is_bookmarked: false });
        setItems((prev) =>
          prev.map((it) => (it.timeline_id === selectedItem.timeline_id ? { ...it, is_bookmarked: false } : it))
        );
        setNotice(`Removed bookmark for item ${selectedItem.timeline_id}`);
      } else {
        await bookmarkTimelineItem(caseId, selectedItem.timeline_id, bookmarkNote || undefined);
        setSelectedItem({ ...selectedItem, is_bookmarked: true });
        setItems((prev) =>
          prev.map((it) => (it.timeline_id === selectedItem.timeline_id ? { ...it, is_bookmarked: true } : it))
        );
        setNotice(`Bookmarked item ${selectedItem.timeline_id}`);
        setBookmarkNote("");
      }
      setTimeout(() => setNotice(null), 3000);
    } catch (err: any) {
      setError(`Bookmark operation failed: ${err.message}`);
    } finally {
      setBookmarking(false);
    }
  };

  const handleExport = async (format: "json" | "csv") => {
    try {
      const data = await exportUnifiedTimeline(caseId, format, {
        host: filterHost || undefined,
        event_type: filterEventType || undefined,
        source_layer: filterLayer || undefined,
        epistemic_status: filterEpistemic || undefined,
        collection_status: filterCollection || undefined,
        search_text: filterSearch || undefined,
      });
      const blob = new Blob([data], { type: format === "json" ? "application/json" : "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `case_${caseId}_unified_timeline_${Date.now()}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
      setNotice(`Exported timeline as ${format.toUpperCase()}`);
      setTimeout(() => setNotice(null), 3000);
    } catch (err: any) {
      setError(`Export failed: ${err.message}`);
    }
  };

  const handleResetFilters = () => {
    setFilterHost("");
    setFilterEventType("");
    setFilterLayer("");
    setFilterEpistemic("");
    setFilterCollection("");
    setFilterSearch("");
    setFilterStartTime("");
    setFilterEndTime("");
  };

  // Badges & styling helpers
  const getEpistemicBadge = (status: EpistemicStatus) => {
    switch (status) {
      case "OBSERVED":
        return <span className="badge badge-notice" title="Forensically observed in recorded host/network telemetry">OBSERVED</span>;
      case "INFERRED":
        return <span className="badge badge-warning" title="Analytically inferred via correlation or rule-based reasoning">INFERRED</span>;
      case "UNKNOWN":
      default:
        return <span className="badge badge-neutral" title="Unknown state; telemetry uncollected or missing">UNKNOWN</span>;
    }
  };

  const getCollectionBadge = (status: CollectionStatus) => {
    switch (status) {
      case "SOURCE_AVAILABLE":
        return <span style={{ fontSize: "10px", color: "var(--badge-success-text)", background: "var(--badge-success-bg)", padding: "1px 5px", borderRadius: "2px" }}>AVAILABLE</span>;
      case "SOURCE_UNAVAILABLE":
        return <span style={{ fontSize: "10px", color: "var(--badge-alert-text)", background: "var(--badge-alert-bg)", padding: "1px 5px", borderRadius: "2px" }}>UNAVAILABLE</span>;
      case "RULE_NOT_CONFIGURED":
        return <span style={{ fontSize: "10px", color: "var(--badge-warning-text)", background: "var(--badge-warning-bg)", padding: "1px 5px", borderRadius: "2px" }}>NO_RULE</span>;
      case "TELEMETRY_DROPPED":
        return <span style={{ fontSize: "10px", color: "#b91c1c", background: "#fee2e2", padding: "1px 5px", borderRadius: "2px" }}>DROPPED</span>;
      default:
        return <span style={{ fontSize: "10px", color: "var(--text-muted)", padding: "1px 5px" }}>UNKNOWN</span>;
    }
  };

  const getLayerColor = (layer: TimelineSourceLayer) => {
    switch (layer) {
      case "EVENT": return "#2563eb";
      case "ALERT": return "#dc2626";
      case "EVIDENCE": return "#7c3aed";
      case "HOST_TELEMETRY": return "#059669";
      case "INCIDENT": return "#d97706";
      case "AUDIT": return "#475569";
      default: return "#4b5563";
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px", width: "100%", fontFamily: "var(--font-sans, 'IBM Plex Sans', sans-serif)" }}>
      {/* Header & Status Bar */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "10px",
          padding: "10px 14px",
          background: "var(--bg-surface, #f9f8f5)",
          border: "1px solid var(--border-subtle, #e2e8f0)",
          borderRadius: "2px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <span style={{ fontSize: "13px", fontWeight: 700, letterSpacing: "-0.01em", color: "var(--text-primary)" }}>
            M7.2 Unified Investigation Timeline & Replay
          </span>
          <span style={{ fontSize: "11px", color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>
            Case #{caseId}
          </span>
          <span className="badge badge-neutral" style={{ fontSize: "10px", fontFamily: "var(--font-mono)" }}>
            {totalCount} items
          </span>
          {deterministicHash && (
            <span style={{ fontSize: "10px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }} title="Deterministic Blake2b Projection Fingerprint">
              SHA: {deterministicHash.slice(0, 10)}...
            </span>
          )}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <button className="btn btn-secondary" onClick={() => handleExport("json")} style={{ fontSize: "11px", padding: "3px 8px" }}>
            <ExportIcon /> JSON
          </button>
          <button className="btn btn-secondary" onClick={() => handleExport("csv")} style={{ fontSize: "11px", padding: "3px 8px" }}>
            <ExportIcon /> CSV
          </button>
          <button className="btn btn-secondary" onClick={loadTimelineData} disabled={loading} style={{ fontSize: "11px", padding: "3px 8px" }}>
            <RefreshIcon /> {loading ? "Loading..." : "Refresh"}
          </button>
        </div>
      </div>

      {notice && (
        <div style={{ padding: "6px 12px", background: "var(--badge-success-bg, #f0fdf4)", border: "1px solid var(--badge-success-border, #bbf7d0)", color: "var(--badge-success-text, #166534)", fontSize: "11px", borderRadius: "2px" }}>
          {notice}
        </div>
      )}

      {error && (
        <div style={{ padding: "8px 12px", background: "var(--badge-alert-bg, #fef2f2)", border: "1px solid var(--badge-alert-border, #fecaca)", color: "var(--badge-alert-text, #991b1b)", fontSize: "11px", borderRadius: "2px" }}>
          {error}
        </div>
      )}

      {/* Replay Controller & Scrubber */}
      <div
        className="panel"
        style={{
          padding: "12px 14px",
          background: "var(--bg-surface, #ffffff)",
          border: "1px solid var(--border-subtle, #e2e8f0)",
          display: "flex",
          flexDirection: "column",
          gap: "10px",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
          {/* Transport Controls */}
          <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
            <button
              className="btn btn-secondary"
              title="Jump to Start (Home)"
              onClick={jumpToStart}
              disabled={!replaySession || replaySession.frames.length === 0 || currentFrameIndex === 0}
              style={{ padding: "4px 8px", fontSize: "11px", fontFamily: "var(--font-mono)" }}
            >
              |◀◀
            </button>
            <button
              className="btn btn-secondary"
              title="Previous Evidence"
              onClick={jumpToPrevEvidence}
              disabled={!replaySession || replaySession.frames.length === 0}
              style={{ padding: "4px 8px", fontSize: "11px", fontFamily: "var(--font-mono)" }}
            >
              ◁*
            </button>
            <button
              className="btn btn-secondary"
              title="Step Backward (Left Arrow)"
              onClick={stepBackward}
              disabled={!replaySession || replaySession.frames.length === 0 || currentFrameIndex === 0}
              style={{ padding: "4px 8px", fontSize: "11px", fontFamily: "var(--font-mono)" }}
            >
              |◀
            </button>

            <button
              className={isPlaying ? "btn btn-secondary" : "btn btn-primary"}
              title="Play / Pause (Space)"
              onClick={() => setIsPlaying((p) => !p)}
              disabled={!replaySession || replaySession.frames.length === 0}
              style={{ padding: "4px 14px", fontSize: "12px", fontWeight: 600 }}
            >
              {isPlaying ? "⏸ Pause" : "▶ Play Replay"}
            </button>

            <button
              className="btn btn-secondary"
              title="Step Forward (Right Arrow)"
              onClick={stepForward}
              disabled={!replaySession || replaySession.frames.length === 0 || currentFrameIndex >= (replaySession?.frames.length || 1) - 1}
              style={{ padding: "4px 8px", fontSize: "11px", fontFamily: "var(--font-mono)" }}
            >
              ▶|
            </button>
            <button
              className="btn btn-secondary"
              title="Next Evidence"
              onClick={jumpToNextEvidence}
              disabled={!replaySession || replaySession.frames.length === 0}
              style={{ padding: "4px 8px", fontSize: "11px", fontFamily: "var(--font-mono)" }}
            >
              *▷
            </button>
            <button
              className="btn btn-secondary"
              title="Jump to End (End)"
              onClick={jumpToEnd}
              disabled={!replaySession || replaySession.frames.length === 0 || currentFrameIndex >= (replaySession?.frames.length || 1) - 1}
              style={{ padding: "4px 8px", fontSize: "11px", fontFamily: "var(--font-mono)" }}
            >
              ▶▶|
            </button>
          </div>

          {/* Speed Selector */}
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <span style={{ fontSize: "11px", color: "var(--text-secondary)" }}>Speed:</span>
            {[0.25, 0.5, 1.0, 2.0, 4.0].map((spd) => (
              <button
                key={spd}
                className={playbackSpeed === spd ? "btn btn-primary" : "btn btn-secondary"}
                onClick={() => setPlaybackSpeed(spd)}
                style={{ padding: "2px 6px", fontSize: "10px", fontFamily: "var(--font-mono)" }}
              >
                {spd}x
              </button>
            ))}
          </div>

          {/* Frame Progress Indicator */}
          <div style={{ fontSize: "11px", fontFamily: "var(--font-mono)", color: "var(--text-primary)" }}>
            Frame <strong>{replaySession && replaySession.frames.length > 0 ? currentFrameIndex + 1 : 0}</strong> of{" "}
            <strong>{replaySession?.frames.length || 0}</strong>
            {replaySession?.frames[currentFrameIndex] && (
              <span style={{ marginLeft: "8px", color: "var(--text-muted)" }}>
                [{replaySession.frames[currentFrameIndex].timestamp}]
              </span>
            )}
          </div>
        </div>

        {/* Scrubber Bar */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <input
            type="range"
            min={0}
            max={Math.max(0, (replaySession?.frames.length || 1) - 1)}
            value={currentFrameIndex}
            onChange={handleScrubberChange}
            disabled={!replaySession || replaySession.frames.length <= 1}
            style={{ flex: 1, accentColor: "var(--text-primary)", cursor: "pointer" }}
            aria-label="Investigation timeline scrubber"
          />
        </div>
      </div>

      {/* Multi-Dimensional Filter Bar */}
      <div
        className="panel"
        style={{
          padding: "10px 14px",
          background: "var(--bg-surface, #ffffff)",
          border: "1px solid var(--border-subtle, #e2e8f0)",
          display: "flex",
          flexWrap: "wrap",
          gap: "8px",
          alignItems: "center",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <FilterIcon />
          <span style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Filters:</span>
        </div>

        <input
          type="text"
          placeholder="Filter host..."
          value={filterHost}
          onChange={(e) => setFilterHost(e.target.value)}
          style={{ padding: "3px 6px", fontSize: "11px", width: "110px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
        />

        <input
          type="text"
          placeholder="Filter event type..."
          value={filterEventType}
          onChange={(e) => setFilterEventType(e.target.value)}
          style={{ padding: "3px 6px", fontSize: "11px", width: "120px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
        />

        <select
          value={filterLayer}
          onChange={(e) => setFilterLayer(e.target.value as any)}
          style={{ padding: "3px 6px", fontSize: "11px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
        >
          <option value="">All Layers</option>
          <option value="EVENT">EVENT</option>
          <option value="ALERT">ALERT</option>
          <option value="EVIDENCE">EVIDENCE</option>
          <option value="HOST_TELEMETRY">HOST_TELEMETRY</option>
          <option value="INCIDENT">INCIDENT</option>
          <option value="AUDIT">AUDIT</option>
        </select>

        <select
          value={filterEpistemic}
          onChange={(e) => setFilterEpistemic(e.target.value as any)}
          style={{ padding: "3px 6px", fontSize: "11px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
        >
          <option value="">All Epistemic</option>
          <option value="OBSERVED">OBSERVED</option>
          <option value="INFERRED">INFERRED</option>
          <option value="UNKNOWN">UNKNOWN</option>
        </select>

        <select
          value={filterCollection}
          onChange={(e) => setFilterCollection(e.target.value as any)}
          style={{ padding: "3px 6px", fontSize: "11px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
        >
          <option value="">All Collection</option>
          <option value="SOURCE_AVAILABLE">SOURCE_AVAILABLE</option>
          <option value="SOURCE_UNAVAILABLE">SOURCE_UNAVAILABLE</option>
          <option value="RULE_NOT_CONFIGURED">RULE_NOT_CONFIGURED</option>
          <option value="TELEMETRY_DROPPED">TELEMETRY_DROPPED</option>
        </select>

        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <SearchIcon />
          <input
            type="text"
            placeholder="Search summary..."
            value={filterSearch}
            onChange={(e) => setFilterSearch(e.target.value)}
            style={{ padding: "3px 6px", fontSize: "11px", width: "140px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
          />
        </div>

        <button className="btn btn-secondary" onClick={handleResetFilters} style={{ fontSize: "10px", padding: "3px 6px" }}>
          Reset
        </button>
      </div>

      {/* Main Split Layout: Timeline List (Left) ↔ Detailed Context Inspector (Right) */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 380px", gap: "12px", minHeight: "480px" }}>
        {/* Left Column: Timeline Items Stream */}
        <div
          className="panel"
          style={{
            padding: "0",
            background: "var(--bg-surface, #ffffff)",
            border: "1px solid var(--border-subtle, #e2e8f0)",
            overflowY: "auto",
            maxHeight: "560px",
          }}
        >
          {loading && (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)", fontSize: "12px" }}>
              Projecting canonical timeline from authoritative evidence...
            </div>
          )}

          {!loading && items.length === 0 && (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)", fontSize: "12px" }}>
              No timeline events found within current investigation scope and filters.
            </div>
          )}

          {!loading && items.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column" }}>
              {items.map((it, idx) => {
                const isSelected = selectedItem?.timeline_id === it.timeline_id;
                const isCurrentReplay = replaySession?.frames[currentFrameIndex]?.item?.timeline_id === it.timeline_id;
                const layerCol = getLayerColor(it.source_layer);

                return (
                  <div
                    key={it.timeline_id}
                    onClick={() => setSelectedItem(it)}
                    style={{
                      padding: "8px 12px",
                      cursor: "pointer",
                      borderBottom: "1px solid var(--border-subtle, #f1f5f9)",
                      borderLeft: isSelected
                        ? "4px solid var(--text-primary, #0f172a)"
                        : isCurrentReplay
                        ? "4px solid #2563eb"
                        : "4px solid transparent",
                      background: isSelected
                        ? "var(--bg-selected, #f8fafc)"
                        : isCurrentReplay
                        ? "var(--bg-highlight, #eff6ff)"
                        : "transparent",
                      transition: "background 0.1s ease",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                        <span style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                          #{idx + 1}
                        </span>
                        <span
                          style={{
                            fontSize: "9px",
                            fontWeight: 700,
                            padding: "1px 4px",
                            borderRadius: "2px",
                            color: "#ffffff",
                            backgroundColor: layerCol,
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {it.source_layer}
                        </span>
                        <span style={{ fontSize: "11px", fontFamily: "var(--font-mono)", color: "var(--text-primary)" }}>
                          {it.timestamp}
                        </span>
                        <span style={{ fontSize: "9px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                          [{it.timestamp_precision}]
                        </span>
                      </div>

                      <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                        {it.is_bookmarked && (
                          <span title="Bookmarked" style={{ color: "#d97706", fontSize: "12px" }}>
                            ★
                          </span>
                        )}
                        {getEpistemicBadge(it.epistemic_status)}
                        {getCollectionBadge(it.collection_status)}
                      </div>
                    </div>

                    <div style={{ fontSize: "12px", color: "var(--text-primary)", marginBottom: "4px", lineHeight: "1.3" }}>
                      {it.display_summary}
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
                      <span style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
                        host: <strong>{it.host_id}</strong>
                      </span>
                      <span style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
                        event: <strong>{it.event_type}</strong>
                      </span>
                      {it.entity_refs.slice(0, 2).map((ent) => (
                        <span
                          key={ent}
                          style={{
                            fontSize: "9px",
                            fontFamily: "var(--font-mono)",
                            padding: "0 4px",
                            background: "var(--border-subtle, #f1f5f9)",
                            borderRadius: "2px",
                            color: "var(--text-secondary)",
                          }}
                        >
                          {ent}
                        </span>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Detailed Context & Synchronized Evidence Inspector */}
        <div
          className="panel"
          style={{
            padding: "12px 14px",
            background: "var(--bg-surface, #ffffff)",
            border: "1px solid var(--border-subtle, #e2e8f0)",
            overflowY: "auto",
            maxHeight: "560px",
            display: "flex",
            flexDirection: "column",
            gap: "12px",
          }}
        >
          {!selectedItem && (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)", fontSize: "12px" }}>
              Select a timeline item to inspect forensic context, linked graph entities, and original source evidence.
            </div>
          )}

          {selectedItem && (
            <>
              {/* Item Overview & Bookmark Toggle */}
              <div style={{ borderBottom: "1px solid var(--border-subtle)", paddingBottom: "10px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "6px" }}>
                  <div>
                    <span style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                      {selectedItem.timeline_id}
                    </span>
                    <h4 style={{ margin: "2px 0 0", fontSize: "13px", fontWeight: 700, color: "var(--text-primary)" }}>
                      {selectedItem.event_type}
                    </h4>
                  </div>
                  <button
                    className="btn btn-secondary"
                    onClick={handleToggleBookmark}
                    disabled={bookmarking}
                    style={{ fontSize: "10px", padding: "2px 6px" }}
                  >
                    {selectedItem.is_bookmarked ? "★ Bookmarked" : "☆ Bookmark"}
                  </button>
                </div>

                <div style={{ fontSize: "11px", color: "var(--text-secondary)", lineHeight: "1.4", margin: "4px 0" }}>
                  {selectedItem.display_summary}
                </div>

                <div style={{ display: "flex", gap: "6px", alignItems: "center", marginTop: "6px", flexWrap: "wrap" }}>
                  {getEpistemicBadge(selectedItem.epistemic_status)}
                  {getCollectionBadge(selectedItem.collection_status)}
                  <span style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                    Host: {selectedItem.host_id}
                  </span>
                  <span style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                    Time: {selectedItem.timestamp}
                  </span>
                </div>
              </div>

              {contextLoading && (
                <div style={{ fontSize: "11px", color: "var(--text-muted)", textAlign: "center", padding: "10px" }}>
                  Resolving graph entities & evidence linkage...
                </div>
              )}

              {/* Traceable Forensic Path */}
              {itemContext && itemContext.traceable_path && itemContext.traceable_path.length > 0 && (
                <div>
                  <span style={{ fontSize: "11px", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase" }}>
                    Traceable Forensic Path
                  </span>
                  <div style={{ display: "flex", flexDirection: "column", gap: "4px", marginTop: "6px" }}>
                    {itemContext.traceable_path.map((step, sIdx) => (
                      <div
                        key={sIdx}
                        style={{
                          fontSize: "10px",
                          fontFamily: "var(--font-mono)",
                          padding: "4px 6px",
                          background: "var(--bg-subtle, #f8fafc)",
                          borderLeft: "2px solid var(--text-secondary)",
                          borderRadius: "2px",
                        }}
                      >
                        <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>{step.level}</span>: {step.id} ({step.type}) [{step.epistemic_status}]
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Synchronized Graph Entities */}
              {itemContext && itemContext.linked_entities && itemContext.linked_entities.length > 0 && (
                <div>
                  <span style={{ fontSize: "11px", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase" }}>
                    Synchronized Graph Entities ({itemContext.linked_entities.length})
                  </span>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "4px", marginTop: "6px" }}>
                    {itemContext.linked_entities.map((ent: any) => (
                      <button
                        key={ent.entity_key}
                        className="btn btn-secondary"
                        onClick={() => onSelectEntityKey && onSelectEntityKey(ent.entity_key)}
                        style={{ fontSize: "10px", padding: "2px 6px", fontFamily: "var(--font-mono)" }}
                        title="Pivot to entity in attack graph"
                      >
                        {ent.entity_key} ({ent.entity_type})
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Synchronized Alerts & Evidence */}
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                {selectedItem.source_layer === "EVENT" && onSelectEventId && (
                  <button
                    className="btn btn-secondary"
                    onClick={() => onSelectEventId(selectedItem.source_id)}
                    style={{ fontSize: "10px", padding: "4px 8px", textAlign: "left" }}
                  >
                    View Source Canonical Event #{selectedItem.source_id}
                  </button>
                )}

                {selectedItem.source_layer === "ALERT" && onSelectAlertId && (
                  <button
                    className="btn btn-secondary"
                    onClick={() => onSelectAlertId(parseInt(selectedItem.source_id, 10))}
                    style={{ fontSize: "10px", padding: "4px 8px", textAlign: "left" }}
                  >
                    Inspect Detection Alert #{selectedItem.source_id}
                  </button>
                )}
              </div>

              {/* Provenance Metadata */}
              {selectedItem.provenance && Object.keys(selectedItem.provenance).length > 0 && (
                <div>
                  <span style={{ fontSize: "11px", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase" }}>
                    Provenance
                  </span>
                  <pre
                    style={{
                      fontSize: "9px",
                      fontFamily: "var(--font-mono)",
                      background: "var(--bg-subtle, #f8fafc)",
                      padding: "6px",
                      borderRadius: "2px",
                      overflowX: "auto",
                      marginTop: "4px",
                      border: "1px solid var(--border-subtle)",
                    }}
                  >
                    {JSON.stringify(selectedItem.provenance, null, 2)}
                  </pre>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
