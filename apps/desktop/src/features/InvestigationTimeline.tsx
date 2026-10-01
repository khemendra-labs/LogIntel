import React, { useState } from "react";
import { SeverityBadge } from "../components/StatusBadge";
import { TimelineItem, TimelineItemType } from "../types/incidents";

interface InvestigationTimelineProps {
  timeline: TimelineItem[];
  onSelectAlertId?: (alertId: number) => void;
  onSelectEventId?: (eventId: string) => void;
}

export function InvestigationTimeline({
  timeline,
  onSelectAlertId,
  onSelectEventId,
}: InvestigationTimelineProps) {
  const [filterType, setFilterType] = useState<string>("ALL");
  const [expandedItemId, setExpandedItemId] = useState<string | null>(null);

  const filteredItems = timeline.filter((item) => {
    if (filterType === "ALL") return true;
    return item.item_type === filterType;
  });

  const milestoneCount = timeline.filter((i) => i.item_type === "MILESTONE").length;
  const alertCount = timeline.filter((i) => i.item_type === "ALERT").length;
  const eventCount = timeline.filter((i) => i.item_type === "EVENT").length;

  const getItemDotColor = (type: TimelineItemType) => {
    switch (type) {
      case "MILESTONE":
        return "#0284c7"; // Cyan/blue
      case "ALERT":
        return "#dc2626"; // Crimson
      case "EVENT":
        return "#64748b"; // Slate
      default:
        return "#94a3b8";
    }
  };

  return (
    <div className="investigation-timeline-container" style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
      {/* Filter toolbar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", gap: "6px" }}>
          <button
            className={`btn btn-secondary ${filterType === "ALL" ? "active" : ""}`}
            style={{ padding: "3px 8px", fontSize: "11px", fontWeight: filterType === "ALL" ? 700 : 400 }}
            onClick={() => setFilterType("ALL")}
          >
            All Stream ({timeline.length})
          </button>
          <button
            className={`btn btn-secondary ${filterType === "MILESTONE" ? "active" : ""}`}
            style={{ padding: "3px 8px", fontSize: "11px" }}
            onClick={() => setFilterType("MILESTONE")}
          >
            Milestones ({milestoneCount})
          </button>
          <button
            className={`btn btn-secondary ${filterType === "ALERT" ? "active" : ""}`}
            style={{ padding: "3px 8px", fontSize: "11px" }}
            onClick={() => setFilterType("ALERT")}
          >
            Alerts ({alertCount})
          </button>
          <button
            className={`btn btn-secondary ${filterType === "EVENT" ? "active" : ""}`}
            style={{ padding: "3px 8px", fontSize: "11px" }}
            onClick={() => setFilterType("EVENT")}
          >
            Telemetry Events ({eventCount})
          </button>
        </div>

        <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
          Showing {filteredItems.length} chronologically sorted items
        </span>
      </div>

      {/* Timeline Stream */}
      <div
        style={{
          position: "relative",
          paddingLeft: "24px",
          borderLeft: "2px solid var(--border-subtle)",
          marginLeft: "12px",
          display: "flex",
          flexDirection: "column",
          gap: "14px",
        }}
      >
        {filteredItems.map((item) => {
          const isExpanded = expandedItemId === item.id;
          const hasDetails = item.details && Object.keys(item.details).length > 0;
          const dotColor = getItemDotColor(item.item_type);

          return (
            <div
              key={item.id}
              style={{
                position: "relative",
                background: "var(--bg-surface)",
                border: "1px solid var(--border-subtle)",
                borderRadius: "2px",
                padding: "10px 14px",
              }}
            >
              {/* Timeline rail marker */}
              <div
                style={{
                  position: "absolute",
                  left: "-31px",
                  top: "14px",
                  width: "12px",
                  height: "12px",
                  borderRadius: "50%",
                  background: dotColor,
                  border: "2px solid var(--bg-surface)",
                  boxShadow: "0 0 0 1px var(--border-subtle)",
                }}
              />

              {/* Item Header */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "4px" }}>
                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  <span
                    className="badge"
                    style={{
                      background: "var(--bg-surface-subtle)",
                      border: "1px solid var(--border-strong)",
                      fontSize: "9px",
                      fontWeight: 700,
                      color: dotColor,
                    }}
                  >
                    {item.item_type}
                  </span>

                  {item.severity && <SeverityBadge severity={item.severity} />}

                  <strong style={{ fontSize: "12px", color: "var(--text-primary)" }}>{item.title}</strong>
                </div>

                <span
                  style={{
                    fontSize: "11px",
                    fontFamily: "var(--font-mono)",
                    color: "var(--text-muted)",
                  }}
                >
                  {new Date(item.timestamp).toISOString().replace("T", " ").replace("Z", " UTC")}
                </span>
              </div>

              {/* Item Summary */}
              <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginBottom: "6px" }}>
                {item.summary}
              </p>

              {/* Entity tags & Action links */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "6px" }}>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                  {item.entity_keys &&
                    item.entity_keys.map((ek) => (
                      <span
                        key={ek}
                        className="badge badge-neutral"
                        style={{ fontSize: "10px", padding: "1px 5px", fontFamily: "var(--font-mono)" }}
                      >
                        {ek}
                      </span>
                    ))}
                </div>

                <div style={{ display: "flex", gap: "6px" }}>
                  {item.item_type === "ALERT" && item.ref_id && onSelectAlertId && (
                    <button
                      className="btn btn-secondary"
                      style={{ padding: "2px 6px", fontSize: "10px" }}
                      onClick={() => onSelectAlertId(parseInt(item.ref_id!))}
                    >
                      View Alert #{item.ref_id}
                    </button>
                  )}

                  {item.item_type === "EVENT" && item.ref_id && onSelectEventId && (
                    <button
                      className="btn btn-secondary"
                      style={{ padding: "2px 6px", fontSize: "10px" }}
                      onClick={() => onSelectEventId(item.ref_id!)}
                    >
                      View Event {item.ref_id.slice(0, 8)}...
                    </button>
                  )}

                  {hasDetails && (
                    <button
                      className="btn btn-secondary"
                      style={{ padding: "2px 6px", fontSize: "10px" }}
                      onClick={() => setExpandedItemId(isExpanded ? null : item.id)}
                    >
                      {isExpanded ? "Hide Details" : "Inspect Details"}
                    </button>
                  )}
                </div>
              </div>

              {/* Expanded Details */}
              {isExpanded && hasDetails && (
                <div style={{ marginTop: "8px" }}>
                  <pre
                    style={{
                      padding: "8px",
                      background: "var(--bg-surface-subtle)",
                      border: "1px solid var(--border-subtle)",
                      borderRadius: "2px",
                      fontFamily: "var(--font-mono)",
                      fontSize: "10px",
                      overflowX: "auto",
                    }}
                  >
                    {JSON.stringify(item.details, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          );
        })}

        {filteredItems.length === 0 && (
          <div style={{ padding: "20px", color: "var(--text-muted)", textAlign: "center" }}>
            No timeline stream items match the selected filter.
          </div>
        )}
      </div>
    </div>
  );
}
