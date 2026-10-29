import { describe, expect, it } from "vitest";
import { padTimelineBuckets, TimeSeriesPoint } from "../components/charts/TimeSeriesChart";

describe("Dashboard Data Transformation & Bucket Padding", () => {
  it("pads completely empty raw timeline with continuous 0-count hourly buckets", () => {
    const raw: TimeSeriesPoint[] = [];
    const hours = 24;
    const padded = padTimelineBuckets(raw, hours);

    expect(padded.length).toBe(hours);
    expect(padded.every((p) => p.count === 0)).toBe(true);

    // Verify buckets are in strictly ascending chronological order
    for (let i = 1; i < padded.length; i++) {
      const prev = new Date(padded[i - 1].bucket).getTime();
      const curr = new Date(padded[i].bucket).getTime();
      expect(curr).toBeGreaterThan(prev);
      expect(curr - prev).toBe(3600 * 1000); // exactly 1 hour apart
    }
  });

  it("preserves known event counts and pads missing hours in between", () => {
    const now = new Date();
    // Simulate events 2 hours ago
    const twoHoursAgo = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours() - 2, 0, 0));
    const rawBucket = twoHoursAgo.toISOString().slice(0, 13) + ":00:00Z";

    const raw: TimeSeriesPoint[] = [
      { bucket: rawBucket, count: 42 },
    ];

    const hours = 6;
    const padded = padTimelineBuckets(raw, hours);

    expect(padded.length).toBe(hours);
    const matched = padded.find((p) => p.bucket === rawBucket);
    expect(matched).toBeDefined();
    expect(matched?.count).toBe(42);

    // Remaining 5 buckets must have count 0
    const zeroBuckets = padded.filter((p) => p.count === 0);
    expect(zeroBuckets.length).toBe(hours - 1);
  });

  it("aggregates multiple data points falling into the same hourly bucket", () => {
    const now = new Date();
    const targetHour = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours() - 1, 0, 0));
    const isoHour = targetHour.toISOString().slice(0, 13) + ":00:00Z";

    const raw: TimeSeriesPoint[] = [
      { bucket: isoHour, count: 10 },
      { bucket: targetHour.toISOString(), count: 15 }, // same hour, full ISO
    ];

    const padded = padTimelineBuckets(raw, 4);
    const matched = padded.find((p) => p.bucket === isoHour);
    expect(matched?.count).toBe(25);
  });

  it("handles various time window spans (6h, 12h, 24h, 72h, 168h)", () => {
    for (const h of [6, 12, 24, 72, 168]) {
      const padded = padTimelineBuckets([], h);
      expect(padded.length).toBe(h);
    }
  });
});
