import React, { useMemo, useState } from "react";

export interface TimeSeriesPoint {
  bucket: string; // ISO string e.g. "2026-10-21T08:00:00Z"
  count: number;
}

interface TimeSeriesChartProps {
  data: TimeSeriesPoint[];
  hours: number;
  height?: number;
  onSelectBucket?: (point: TimeSeriesPoint) => void;
  loading?: boolean;
}

/**
 * Generates continuous hourly UTC buckets for the specified window duration,
 * padding missing intervals with count 0 to prevent distorted or compressed charts.
 */
export function padTimelineBuckets(rawTimeline: TimeSeriesPoint[], hours: number): TimeSeriesPoint[] {
  const countMap = new Map<string, number>();
  for (const pt of rawTimeline) {
    // Normalize to YYYY-MM-DDTHH:00:00Z
    try {
      const dt = new Date(pt.bucket);
      const isoHour = dt.toISOString().slice(0, 13) + ":00:00Z";
      countMap.set(isoHour, (countMap.get(isoHour) || 0) + pt.count);
    } catch {
      countMap.set(pt.bucket, pt.count);
    }
  }

  const now = new Date();
  const endHour = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours(), 0, 0));
  const points: TimeSeriesPoint[] = [];

  for (let i = hours - 1; i >= 0; i--) {
    const d = new Date(endHour.getTime() - i * 3600 * 1000);
    const key = d.toISOString().slice(0, 13) + ":00:00Z";
    points.push({
      bucket: key,
      count: countMap.get(key) || 0,
    });
  }

  return points;
}

export function TimeSeriesChart({
  data,
  hours,
  height = 180,
  onSelectBucket,
  loading = false,
}: TimeSeriesChartProps) {
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);

  // Generate continuous padded buckets
  const paddedData = useMemo(() => {
    return padTimelineBuckets(data || [], hours);
  }, [data, hours]);

  // Derived metrics
  const { maxCount, totalCount, avgCount } = useMemo(() => {
    let max = 0;
    let tot = 0;
    for (const pt of paddedData) {
      if (pt.count > max) max = pt.count;
      tot += pt.count;
    }
    const avg = paddedData.length > 0 ? (tot / paddedData.length).toFixed(1) : "0.0";
    return {
      maxCount: Math.max(max, 5), // Provide minimal headroom if 0 or low
      totalCount: tot,
      avgCount: avg,
    };
  }, [paddedData]);

  // SVG Geometry Dimensions
  const svgWidth = 680;
  const svgHeight = height;
  const paddingLeft = 45;
  const paddingRight = 20;
  const paddingTop = 15;
  const paddingBottom = 25;

  const chartWidth = svgWidth - paddingLeft - paddingRight;
  const chartHeight = svgHeight - paddingTop - paddingBottom;

  // Coordinate computation
  const coordinates = useMemo(() => {
    if (paddedData.length === 0) return [];
    const stepX = chartWidth / Math.max(paddedData.length - 1, 1);

    return paddedData.map((pt, idx) => {
      const x = paddingLeft + idx * stepX;
      const y = paddingTop + chartHeight - (pt.count / maxCount) * chartHeight;
      return { x, y, pt, idx };
    });
  }, [paddedData, chartWidth, chartHeight, paddingLeft, paddingTop, maxCount]);

  // SVG Path strings
  const { linePath, areaPath } = useMemo(() => {
    if (coordinates.length === 0) return { linePath: "", areaPath: "" };

    const first = coordinates[0];
    let lPath = `M ${first.x.toFixed(1)} ${first.y.toFixed(1)}`;
    for (let i = 1; i < coordinates.length; i++) {
      const c = coordinates[i];
      lPath += ` L ${c.x.toFixed(1)} ${c.y.toFixed(1)}`;
    }

    const baselineY = paddingTop + chartHeight;
    const last = coordinates[coordinates.length - 1];
    const aPath = `${lPath} L ${last.x.toFixed(1)} ${baselineY} L ${first.x.toFixed(1)} ${baselineY} Z`;

    return { linePath: lPath, areaPath: aPath };
  }, [coordinates, paddingTop, chartHeight]);

  const activePoint = hoverIndex !== null && coordinates[hoverIndex] ? coordinates[hoverIndex] : null;

  if (loading) {
    return (
      <div
        style={{
          height: `${height}px`,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "var(--text-muted)",
          fontSize: "12px",
          fontFamily: "var(--font-mono)",
        }}
      >
        Aggregating hourly telemetry statistics...
      </div>
    );
  }

  return (
    <div style={{ position: "relative", width: "100%" }}>
      {/* Top summary strip */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "8px",
          fontSize: "11px",
          fontFamily: "var(--font-mono)",
          color: "var(--text-secondary)",
        }}
      >
        <div style={{ display: "flex", gap: "14px" }}>
          <span>
            Window Total:{" "}
            <strong style={{ color: "var(--text-primary)" }}>{totalCount.toLocaleString()}</strong> events
          </span>
          <span>
            Peak:{" "}
            <strong style={{ color: "var(--text-primary)" }}>{maxCount.toLocaleString()}</strong>/hr
          </span>
          <span>
            Avg: <strong style={{ color: "var(--text-primary)" }}>{avgCount}</strong>/hr
          </span>
        </div>
        <span style={{ color: "var(--text-muted)" }}>
          {hours >= 24 ? `${(hours / 24).toFixed(0)}d window` : `${hours}h window`} (UTC Buckets)
        </span>
      </div>

      {/* SVG Canvas */}
      <svg
        viewBox={`0 0 ${svgWidth} ${svgHeight}`}
        style={{ width: "100%", height: "auto", display: "block", overflow: "visible" }}
        onMouseLeave={() => setHoverIndex(null)}
      >
        {/* Background Grid Lines (3 horizontal levels) */}
        {[0, 0.5, 1].map((ratio) => {
          const y = paddingTop + chartHeight * (1 - ratio);
          const val = Math.round(maxCount * ratio);
          return (
            <g key={ratio}>
              <line
                x1={paddingLeft}
                y1={y}
                x2={paddingLeft + chartWidth}
                y2={y}
                stroke="var(--chart-grid)"
                strokeDasharray="2 3"
                strokeWidth="1"
              />
              <text
                x={paddingLeft - 8}
                y={y + 4}
                textAnchor="end"
                fontSize="10"
                fontFamily="var(--font-mono)"
                fill="var(--chart-axis-text)"
              >
                {val.toLocaleString()}
              </text>
            </g>
          );
        })}

        {/* Shaded Area Under Curve */}
        {areaPath && (
          <path d={areaPath} fill="var(--chart-area-fill)" />
        )}

        {/* Primary Trend Line */}
        {linePath && (
          <path
            d={linePath}
            fill="none"
            stroke="var(--chart-line)"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        )}

        {/* X-Axis Baseline */}
        <line
          x1={paddingLeft}
          y1={paddingTop + chartHeight}
          x2={paddingLeft + chartWidth}
          y2={paddingTop + chartHeight}
          stroke="var(--border-strong)"
          strokeWidth="1"
        />

        {/* X-Axis Ticks (Start, Middle, End) */}
        {coordinates.length > 0 && (
          <>
            <text
              x={paddingLeft}
              y={paddingTop + chartHeight + 16}
              textAnchor="start"
              fontSize="10"
              fontFamily="var(--font-mono)"
              fill="var(--chart-axis-text)"
            >
              {new Date(coordinates[0].pt.bucket).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
            </text>
            <text
              x={paddingLeft + chartWidth / 2}
              y={paddingTop + chartHeight + 16}
              textAnchor="middle"
              fontSize="10"
              fontFamily="var(--font-mono)"
              fill="var(--chart-axis-text)"
            >
              {new Date(coordinates[Math.floor(coordinates.length / 2)].pt.bucket).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
              })}
            </text>
            <text
              x={paddingLeft + chartWidth}
              y={paddingTop + chartHeight + 16}
              textAnchor="end"
              fontSize="10"
              fontFamily="var(--font-mono)"
              fill="var(--chart-axis-text)"
            >
              Now
            </text>
          </>
        )}

        {/* Interactive hover indicator */}
        {activePoint && (
          <g>
            <line
              x1={activePoint.x}
              y1={paddingTop}
              x2={activePoint.x}
              y2={paddingTop + chartHeight}
              stroke="var(--border-dark)"
              strokeDasharray="3 3"
              strokeWidth="1"
            />
            <circle
              cx={activePoint.x}
              cy={activePoint.y}
              r="4.5"
              fill="var(--chart-line)"
              stroke="var(--bg-surface)"
              strokeWidth="2"
            />
          </g>
        )}

        {/* Invisible mouse detection bars */}
        {coordinates.map((c) => {
          const barWidth = chartWidth / Math.max(coordinates.length, 1);
          return (
            <rect
              key={c.idx}
              x={c.x - barWidth / 2}
              y={paddingTop}
              width={barWidth}
              height={chartHeight}
              fill="transparent"
              style={{ cursor: "crosshair" }}
              onMouseEnter={() => setHoverIndex(c.idx)}
              onClick={() => onSelectBucket?.(c.pt)}
            />
          );
        })}
      </svg>

      {/* Floating Hover Tooltip */}
      {activePoint && (
        <div
          className="chart-tooltip-box"
          style={{
            position: "absolute",
            top: `${Math.max(10, (activePoint.y / svgHeight) * height - 30)}px`,
            left: `${Math.min(
              Math.max(paddingLeft, (activePoint.x / svgWidth) * 100),
              80
            )}%`,
            transform: "translate(-50%, -100%)",
            zIndex: 10,
          }}
        >
          <div style={{ fontWeight: 600 }}>{activePoint.pt.count.toLocaleString()} events</div>
          <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>
            {new Date(activePoint.pt.bucket).toLocaleString()}
          </div>
        </div>
      )}
    </div>
  );
}
