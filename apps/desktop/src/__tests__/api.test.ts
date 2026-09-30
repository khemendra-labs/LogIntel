import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  fetchHandshake,
  fetchEvents,
  fetchSystemStatus,
  setEngineToken,
  setTokenProvider,
} from "../lib/api";

describe("Frontend API Client and Authentication", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    setEngineToken(null);
    setTokenProvider(null);
  });

  it("fetchHandshake queries /handshake without requiring token", async () => {
    const mockHandshake = {
      service: "logintel-engine",
      version: "0.1.0",
      api_version: "v1",
      status: "ready",
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockHandshake,
    } as Response);

    const info = await fetchHandshake();
    expect(info.service).toBe("logintel-engine");
    expect(info.status).toBe("ready");
    expect(fetchSpy).toHaveBeenCalledWith("http://127.0.0.1:41721/api/v1/handshake");
  });

  it("attaches Authorization Bearer header when token is set", async () => {
    setEngineToken("secret_token_12345");

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => ({ app_name: "LogIntel", version: "0.1.0" }),
    } as Response);

    await fetchSystemStatus();

    expect(fetchSpy).toHaveBeenCalled();
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe("http://127.0.0.1:41721/api/v1/system/status");
    const headers = init?.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer secret_token_12345");
  });

  it("constructs proper query parameters for filtered event queries", async () => {
    setEngineToken("valid_token");

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => ({ items: [], total: 0, limit: 25, offset: 50 }),
    } as Response);

    await fetchEvents({
      limit: 25,
      offset: 50,
      source: "auth.log",
      severity: "ALERT",
      username: "attacker",
      outcome: "FAILURE",
      search: "ssh",
      sortOrder: "DESC",
    });

    expect(fetchSpy).toHaveBeenCalled();
    const [url] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("limit=25");
    expect(url).toContain("offset=50");
    expect(url).toContain("source=auth.log");
    expect(url).toContain("severity=ALERT");
    expect(url).toContain("username=attacker");
    expect(url).toContain("outcome=FAILURE");
    expect(url).toContain("search=ssh");
    expect(url).toContain("sort_order=DESC");
  });

  it("throws clear error on HTTP failure", async () => {
    setEngineToken("bad_token");

    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
    } as Response);

    await expect(fetchSystemStatus()).rejects.toThrow("Failed to fetch system status: Unauthorized");
  });

  it("fetchAlerts constructs proper query parameters", async () => {
    setEngineToken("alert_token");

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => ({ items: [], total: 0, limit: 10, offset: 0 }),
    } as Response);

    const { fetchAlerts } = await import("../lib/api");
    await fetchAlerts({
      status: "OPEN",
      severity: "CRITICAL",
      host: "srv-01",
      rule_id: "auth.ssh_bruteforce",
      limit: 10,
      offset: 0,
    });

    expect(fetchSpy).toHaveBeenCalled();
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/api/v1/alerts?");
    expect(url).toContain("status=OPEN");
    expect(url).toContain("severity=CRITICAL");
    expect(url).toContain("host=srv-01");
    expect(url).toContain("rule_id=auth.ssh_bruteforce");
    expect(url).toContain("limit=10");
    const headers = init?.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer alert_token");
  });

  it("fetchAlertDetail queries alert by ID", async () => {
    setEngineToken("detail_token");

    const mockDetail = {
      alert: { id: 42, title: "Test Alert", status: "OPEN" },
      detections: [],
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockDetail,
    } as Response);

    const { fetchAlertDetail } = await import("../lib/api");
    const result = await fetchAlertDetail(42);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/alerts/42",
      expect.objectContaining({
        headers: expect.any(Headers),
      })
    );
    expect(result.alert.id).toBe(42);
  });

  it("updateAlertStatus sends PATCH with status and resolution note", async () => {
    setEngineToken("patch_token");

    const mockUpdatedAlert = { id: 7, status: "RESOLVED", resolution_note: "Fixed" };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockUpdatedAlert,
    } as Response);

    const { updateAlertStatus } = await import("../lib/api");
    const result = await updateAlertStatus(7, "RESOLVED", "Fixed");

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/alerts/7/status",
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify({ status: "RESOLVED", resolution_note: "Fixed" }),
      })
    );
    expect(result.status).toBe("RESOLVED");
  });

  it("fetchDetectionRules queries rules catalog with optional filters", async () => {
    setEngineToken("rules_token");

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => ({ items: [], total: 16 }),
    } as Response);

    const { fetchDetectionRules } = await import("../lib/api");
    const result = await fetchDetectionRules("AUTH", true);

    expect(fetchSpy).toHaveBeenCalled();
    const [url] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/api/v1/detection/rules?");
    expect(url).toContain("category=AUTH");
    expect(url).toContain("enabled=true");
    expect(result.total).toBe(16);
  });

  it("fetchDetectionRuleDetail queries rule by ID", async () => {
    setEngineToken("rule_detail_token");

    const mockRuleDetail = {
      rule: { id: "auth.ssh_bruteforce", name: "SSH Brute Force" },
      yaml_definition: "id: auth.ssh_bruteforce\n",
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockRuleDetail,
    } as Response);

    const { fetchDetectionRuleDetail } = await import("../lib/api");
    const result = await fetchDetectionRuleDetail("auth.ssh_bruteforce");

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/detection/rules/auth.ssh_bruteforce",
      expect.objectContaining({
        headers: expect.any(Headers),
      })
    );
    expect(result.rule.id).toBe("auth.ssh_bruteforce");
    expect(result.yaml_definition).toContain("id: auth.ssh_bruteforce");
  });

  it("invalidates stale cached token on 401 and retries with rotated token", async () => {
    setEngineToken("stale_token_before_restart");
    setTokenProvider(async () => "fresh_token_after_restart");

    // First call returns 401 with stale token, second call with new token returns 200 OK
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ app_name: "LogIntel", version: "0.1.0" }),
      } as Response);

    // Call API: should catch 401, clear cache, acquire new token, and retry
    const status = await fetchSystemStatus();
    expect(status.app_name).toBe("LogIntel");
    expect(fetchSpy).toHaveBeenCalledTimes(2);

    // First request had stale token
    const firstHeaders = fetchSpy.mock.calls[0][1]?.headers as Headers;
    expect(firstHeaders.get("Authorization")).toBe("Bearer stale_token_before_restart");

    // Second request had rotated fresh token
    const secondHeaders = fetchSpy.mock.calls[1][1]?.headers as Headers;
    expect(secondHeaders.get("Authorization")).toBe("Bearer fresh_token_after_restart");
  });
});

