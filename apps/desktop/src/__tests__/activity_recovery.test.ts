import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("Activity Page Recovery & Transient Error Classification", () => {
  // Logic mirror of isTransientNetworkError from ActivityPage
  const isTransientNetworkError = (err: any): boolean => {
    const msg = (err?.message || "").toLowerCase();
    if (
      msg.includes("unauthorized") ||
      msg.includes("forbidden") ||
      msg.includes("401") ||
      msg.includes("403") ||
      msg.includes("422")
    ) {
      return false;
    }
    return (
      msg.includes("load failed") ||
      msg.includes("failed to fetch") ||
      msg.includes("networkerror") ||
      msg.includes("connection refused") ||
      msg.includes("econnrefused")
    );
  };

  it("identifies WebKitGTK connection failure ('Load failed') as transient", () => {
    expect(isTransientNetworkError(new Error("Load failed"))).toBe(true);
  });

  it("identifies Fetch network errors ('Failed to fetch') as transient", () => {
    expect(isTransientNetworkError(new Error("Failed to fetch"))).toBe(true);
  });

  it("identifies TCP connection refused as transient", () => {
    expect(isTransientNetworkError(new Error("connect ECONNREFUSED 127.0.0.1:41721"))).toBe(true);
  });

  it("rejects HTTP 401 Unauthorized from being classified as transient", () => {
    expect(isTransientNetworkError(new Error("Unauthorized: Missing Authorization header"))).toBe(false);
    expect(isTransientNetworkError(new Error("HTTP 401 Unauthorized"))).toBe(false);
  });

  it("rejects HTTP 403 Forbidden from being classified as transient", () => {
    expect(isTransientNetworkError(new Error("Forbidden access to resource"))).toBe(false);
  });

  it("rejects HTTP 422 Unprocessable Entity from being classified as transient", () => {
    expect(isTransientNetworkError(new Error("Validation Error: 422 Unprocessable Entity"))).toBe(false);
  });

  it("simulates bounded retry loop up to 2 attempts on transient failure", async () => {
    let callCount = 0;
    const maxRetries = 2;
    let retryCount = 0;

    const mockFetch = vi.fn().mockImplementation(() => {
      callCount++;
      if (callCount <= 2) {
        throw new Error("Load failed");
      }
      return Promise.resolve({ items: [{ id: "evt_1" }], total: 1 });
    });

    const runWithRetry = async () => {
      try {
        return await mockFetch();
      } catch (err: any) {
        if (isTransientNetworkError(err) && retryCount < maxRetries) {
          retryCount++;
          return runWithRetry();
        }
        throw err;
      }
    };

    const result = await runWithRetry();
    expect(result.items.length).toBe(1);
    expect(callCount).toBe(3); // 1 initial + 2 retries
    expect(retryCount).toBe(2);
  });

  it("stops and preserves error if persistent failure exceeds 2 retries", async () => {
    let callCount = 0;
    const maxRetries = 2;
    let retryCount = 0;

    const mockFetch = vi.fn().mockImplementation(() => {
      callCount++;
      throw new Error("Load failed");
    });

    const runWithRetry = async () => {
      try {
        return await mockFetch();
      } catch (err: any) {
        if (isTransientNetworkError(err) && retryCount < maxRetries) {
          retryCount++;
          return runWithRetry();
        }
        throw err;
      }
    };

    await expect(runWithRetry()).rejects.toThrow("Load failed");
    expect(callCount).toBe(3); // 1 initial + 2 retries
    expect(retryCount).toBe(2);
  });

  it("does not retry when authorization error occurs", async () => {
    let callCount = 0;
    let retryCount = 0;

    const mockFetch = vi.fn().mockImplementation(() => {
      callCount++;
      throw new Error("Unauthorized: Invalid Bearer token");
    });

    const runWithRetry = async () => {
      try {
        return await mockFetch();
      } catch (err: any) {
        if (isTransientNetworkError(err) && retryCount < 2) {
          retryCount++;
          return runWithRetry();
        }
        throw err;
      }
    };

    await expect(runWithRetry()).rejects.toThrow("Unauthorized");
    expect(callCount).toBe(1); // Exactly 1 call, zero retries
    expect(retryCount).toBe(0);
  });
});
