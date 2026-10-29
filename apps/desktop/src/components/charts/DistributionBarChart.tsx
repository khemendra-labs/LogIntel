import React from "react";

export interface DistributionItem {
  key: string;
  label: string;
  count: number;
  badge?: React.ReactNode;
}

interface DistributionBarChartProps {
  items: DistributionItem[];
  total?: number;
  emptyMessage?: string;
  onSelectItem?: (item: DistributionItem) => void;
  maxDisplay?: number;
  unitLabel?: string;
}

export function DistributionBarChart({
  items,
  total,
  emptyMessage = "No distribution data available in this scope.",
  onSelectItem,
  maxDisplay = 8,
  unitLabel = "events",
}: DistributionBarChartProps) {
  const displayItems = items.slice(0, maxDisplay);
  const derivedTotal = total !== undefined ? total : items.reduce((acc, it) => acc + it.count, 0);
  const maxVal = Math.max(...displayItems.map((it) => it.count), 1);

  if (displayItems.length === 0) {
    return (
      <div
        style={{
          padding: "16px",
          textAlign: "center",
          color: "var(--text-muted)",
          fontSize: "12px",
          fontStyle: "italic",
        }}
      >
        {emptyMessage}
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
      {displayItems.map((item) => {
        const pctOfTotal = derivedTotal > 0 ? ((item.count / derivedTotal) * 100).toFixed(1) : "0.0";
        const widthPct = Math.max(2, Math.min(100, (item.count / maxVal) * 100));

        return (
          <div
            key={item.key}
            onClick={() => onSelectItem?.(item)}
            title={onSelectItem ? `Click to filter by ${item.label}` : undefined}
            style={{
              cursor: onSelectItem ? "pointer" : "default",
              display: "flex",
              flexDirection: "column",
              gap: "3px",
              padding: "4px 6px",
              borderRadius: "2px",
              transition: "background-color 0.1s ease",
            }}
            className={onSelectItem ? "distribution-row-clickable" : undefined}
          >
            {/* Header: Label + Count + Percentage */}
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                fontSize: "11px",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "6px", minWidth: 0 }}>
                {item.badge}
                <span
                  className="mono-cell"
                  style={{
                    fontWeight: 500,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    color: "var(--text-primary)",
                  }}
                >
                  {item.label}
                </span>
              </div>
              <div
                className="mono-cell"
                style={{
                  color: "var(--text-secondary)",
                  fontSize: "11px",
                  whiteSpace: "nowrap",
                  marginLeft: "8px",
                }}
              >
                <strong>{item.count.toLocaleString()}</strong>{" "}
                <span style={{ color: "var(--text-muted)", fontSize: "10px" }}>
                  ({pctOfTotal}%)
                </span>
              </div>
            </div>

            {/* Proportion Bar Track */}
            <div
              style={{
                height: "5px",
                width: "100%",
                background: "var(--chart-bar-bg)",
                borderRadius: "1px",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  height: "100%",
                  width: `${widthPct}%`,
                  background: "var(--chart-bar-fill)",
                  borderRadius: "1px",
                  transition: "width 0.2s ease",
                }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
