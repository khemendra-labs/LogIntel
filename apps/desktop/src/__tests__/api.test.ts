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

  it("fetchIncidents constructs proper query parameters and filters", async () => {
    setEngineToken("inc_token_abc");

    const mockResponse = {
      items: [
        {
          id: 1,
          incident_key: "INC-2026-001",
          title: "Multi-stage Brute Force",
          status: "OPEN",
          severity: "CRITICAL",
          primary_host: "srv-db01",
          alert_count: 3,
        },
      ],
      total: 1,
      limit: 20,
      offset: 0,
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    } as Response);

    const { fetchIncidents } = await import("../lib/api");
    const result = await fetchIncidents({
      status: "OPEN",
      severity: "CRITICAL",
      host: "srv-db01",
      user: "root",
      limit: 20,
      offset: 0,
    });

    expect(fetchSpy).toHaveBeenCalled();
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/api/v1/incidents?");
    expect(url).toContain("status=OPEN");
    expect(url).toContain("severity=CRITICAL");
    expect(url).toContain("host=srv-db01");
    expect(url).toContain("user=root");
    expect(url).toContain("limit=20");
    expect(url).toContain("offset=0");
    const headers = init?.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer inc_token_abc");
    expect(result.items.length).toBe(1);
    expect(result.total).toBe(1);
  });

  it("fetchIncidentDetail retrieves complete workspace dossier by ID", async () => {
    setEngineToken("detail_inc_token");

    const mockDossier = {
      incident: {
        id: 42,
        incident_key: "INC-2026-042",
        title: "Compromised Database",
        status: "INVESTIGATING",
      },
      alerts: [{ id: 10, title: "SSH Brute Force", severity: "CRITICAL" }],
      graph: {
        incident_id: 42,
        nodes: [{ id: "host:srv-db01", entity_type: "HOST", label: "srv-db01", metadata: {} }],
        edges: [],
      },
      timeline: [
        {
          id: "alert-10",
          timestamp: "2026-09-30T10:00:00Z",
          item_type: "ALERT",
          title: "SSH Brute Force",
          summary: "Alert triggered",
          entity_keys: ["host:srv-db01"],
          details: {},
        },
      ],
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockDossier,
    } as Response);

    const { fetchIncidentDetail } = await import("../lib/api");
    const result = await fetchIncidentDetail(42);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/incidents/42",
      expect.objectContaining({
        headers: expect.any(Headers),
      })
    );
    expect(result.incident.id).toBe(42);
    expect(result.alerts.length).toBe(1);
    expect(result.graph.nodes.length).toBe(1);
    expect(result.timeline.length).toBe(1);
  });

  it("fetchIncidentAlerts queries linked operational alerts", async () => {
    setEngineToken("inc_alerts_token");

    const mockAlerts = {
      incident_id: 5,
      items: [
        { id: 101, title: "Alert 1", status: "ACKNOWLEDGED" },
        { id: 102, title: "Alert 2", status: "OPEN" },
      ],
      total: 2,
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockAlerts,
    } as Response);

    const { fetchIncidentAlerts } = await import("../lib/api");
    const result = await fetchIncidentAlerts(5);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/incidents/5/alerts",
      expect.objectContaining({
        headers: expect.any(Headers),
      })
    );
    expect(result.incident_id).toBe(5);
    expect(result.items.length).toBe(2);
    expect(result.total).toBe(2);
  });

  it("updateIncidentStatus sends PATCH request with new status and resolution note", async () => {
    setEngineToken("status_patch_token");

    const mockUpdatedIncident = {
      id: 12,
      incident_key: "INC-12",
      status: "CONTAINED",
      resolution_note: "Isolated network port",
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockUpdatedIncident,
    } as Response);

    const { updateIncidentStatus } = await import("../lib/api");
    const result = await updateIncidentStatus(12, "CONTAINED", "Isolated network port");

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/incidents/12/status",
      expect.objectContaining({
        method: "PATCH",
        headers: expect.any(Headers),
        body: JSON.stringify({ status: "CONTAINED", resolution_note: "Isolated network port" }),
      })
    );
    expect(result.status).toBe("CONTAINED");
  });

  it("updateIncidentStatus extracts server detail message on failure", async () => {
    setEngineToken("status_error_token");

    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 400,
      statusText: "Bad Request",
      json: async () => ({ detail: "Invalid incident status transition from 'OPEN' to 'CLOSED'" }),
    } as Response);

    const { updateIncidentStatus } = await import("../lib/api");
    await expect(updateIncidentStatus(12, "CLOSED")).rejects.toThrow(
      "Failed to update incident status: Invalid incident status transition from 'OPEN' to 'CLOSED'"
    );
  });

  it("fetchIncidentAttackGraph retrieves nodes and edges topology", async () => {
    setEngineToken("graph_token");

    const mockGraph = {
      incident_id: 3,
      nodes: [
        { id: "host:srv1", entity_type: "HOST", label: "srv1", metadata: {} },
        { id: "user:alice", entity_type: "USER", label: "alice", metadata: {} },
      ],
      edges: [
        {
          id: "1",
          source: "user:alice",
          target: "host:srv1",
          relationship_type: "AUTHENTICATED_TO",
          confidence: "STRONG",
          evidence_event_ids: ["ev-01"],
          matched_at: "2026-09-30T10:00:00Z",
        },
      ],
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockGraph,
    } as Response);

    const { fetchIncidentAttackGraph } = await import("../lib/api");
    const result = await fetchIncidentAttackGraph(3);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/incidents/3/graph",
      expect.objectContaining({
        headers: expect.any(Headers),
      })
    );
    expect(result.incident_id).toBe(3);
    expect(result.nodes.length).toBe(2);
    expect(result.edges.length).toBe(1);
    expect(result.edges[0].relationship_type).toBe("AUTHENTICATED_TO");
  });

  it("fetchIncidentTimeline retrieves chronologically ordered items", async () => {
    setEngineToken("timeline_token");

    const mockTimeline = {
      incident_id: 9,
      items: [
        {
          id: "alert-1",
          timestamp: "2026-09-30T10:00:00Z",
          item_type: "ALERT",
          title: "Initial Breach",
          summary: "First alert",
          entity_keys: ["host:gateway"],
          details: {},
        },
        {
          id: "milestone-status-CONTAINED",
          timestamp: "2026-09-30T10:15:00Z",
          item_type: "MILESTONE",
          title: "Incident Contained",
          summary: "Status transitioned to CONTAINED",
          entity_keys: [],
          details: {},
        },
      ],
      total: 2,
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockTimeline,
    } as Response);

    const { fetchIncidentTimeline } = await import("../lib/api");
    const result = await fetchIncidentTimeline(9);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/incidents/9/timeline",
      expect.objectContaining({
        headers: expect.any(Headers),
      })
    );
    expect(result.incident_id).toBe(9);
    expect(result.items.length).toBe(2);
    expect(result.items[1].item_type).toBe("MILESTONE");
  });

  it("triggerIncidentCorrelation executes POST to correlate unassigned alerts", async () => {
    setEngineToken("correlate_token");

    const mockResponse = {
      correlated_incidents_count: 2,
      incident_ids: [101, 102],
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    } as Response);

    const { triggerIncidentCorrelation } = await import("../lib/api");
    const result = await triggerIncidentCorrelation();

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/incidents/correlate",
      expect.objectContaining({
        method: "POST",
        headers: expect.any(Headers),
      })
    );
    expect(result.correlated_incidents_count).toBe(2);
    expect(result.incident_ids).toEqual([101, 102]);
  });

  it("triggerIncidentCorrelation throws clear error on API failure", async () => {
    setEngineToken("correlate_token_fail");

    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      json: async () => ({ detail: "Database connection failed during correlation" }),
    } as Response);

    const { triggerIncidentCorrelation } = await import("../lib/api");
    await expect(triggerIncidentCorrelation()).rejects.toThrow(
      "Failed to trigger incident correlation: Database connection failed during correlation"
    );
  });

  // ============================================================================
  // Milestone 4 — Investigation Workspace, Threat Hunting & Attack Path Tests
  // ============================================================================

  it("fetchInvestigationDossier retrieves full investigation dossier by ID", async () => {
    setEngineToken("m4_dossier_token");

    const mockDossier = {
      incident: { id: 7, incident_key: "INC-2026-0007" },
      alerts: [],
      entities: [],
      relationships: [],
      timeline: [],
      attack_path: { incident_id: 7, steps: [], root_causes: [], terminal_targets: [], is_multi_host: false, total_steps: 0 },
      mitre_mappings: [],
      notes: [],
      timeline_total: 0,
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockDossier,
    } as Response);

    const { fetchInvestigationDossier } = await import("../lib/api");
    const result = await fetchInvestigationDossier(7);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/investigations/7",
      expect.objectContaining({ headers: expect.any(Headers) })
    );
    expect(result.incident.id).toBe(7);
  });

  it("fetchAttackPath retrieves reconstructed attack path with steps", async () => {
    setEngineToken("m4_path_token");

    const mockPath = {
      incident_id: 8,
      steps: [
        {
          step_number: 1,
          source_node: "ip:192.168.1.50",
          target_node: "host:srv-01",
          relationship_type: "NETWORK_FLOW",
          stage: "INITIAL_ACCESS",
          confidence: "HIGH",
          nature: "OBSERVED",
          supporting_event_ids: ["evt-01"],
          description: "Inbound traffic",
        },
      ],
      root_causes: ["ip:192.168.1.50"],
      terminal_targets: ["host:srv-01"],
      is_multi_host: false,
      total_steps: 1,
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockPath,
    } as Response);

    const { fetchAttackPath } = await import("../lib/api");
    const result = await fetchAttackPath(8);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/investigations/8/attack-path",
      expect.objectContaining({ headers: expect.any(Headers) })
    );
    expect(result.steps.length).toBe(1);
    expect(result.steps[0].nature).toBe("OBSERVED");
  });

  it("fetchMitreMappings retrieves deterministic MITRE mappings", async () => {
    setEngineToken("m4_mitre_token");

    const mockMitre = {
      incident_id: 8,
      items: [
        {
          technique_id: "T1110.001",
          technique_name: "Password Guessing",
          tactic: "Credential Access",
          rule_id: "auth.ssh_bruteforce",
          rule_name: "SSH Brute Force",
          supporting_alert_ids: [10],
          supporting_event_ids: ["evt-1"],
          confidence: "HIGH",
        },
      ],
      total: 1,
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockMitre,
    } as Response);

    const { fetchMitreMappings } = await import("../lib/api");
    const result = await fetchMitreMappings(8);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/investigations/8/mitre",
      expect.objectContaining({ headers: expect.any(Headers) })
    );
    expect(result.items.length).toBe(1);
    expect(result.items[0].technique_id).toBe("T1110.001");
  });

  it("createInvestigationNote sends POST to record analyst annotation", async () => {
    setEngineToken("m4_note_token");

    const mockNote = {
      id: 1,
      incident_id: 9,
      author: "ForensicAnalyst-1",
      content: "Suspicious lateral movement confirmed from host telemetry.",
      created_at: "2026-09-30T12:00:00Z",
      target_type: "INCIDENT",
      target_id: null,
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockNote,
    } as Response);

    const { createInvestigationNote } = await import("../lib/api");
    const result = await createInvestigationNote(9, {
      author: "ForensicAnalyst-1",
      content: "Suspicious lateral movement confirmed from host telemetry.",
      target_type: "INCIDENT",
    });

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/investigations/9/notes",
      expect.objectContaining({
        method: "POST",
        headers: expect.any(Headers),
        body: JSON.stringify({
          author: "ForensicAnalyst-1",
          content: "Suspicious lateral movement confirmed from host telemetry.",
          target_type: "INCIDENT",
        }),
      })
    );
    expect(result.id).toBe(1);
    expect(result.author).toBe("ForensicAnalyst-1");
  });

  it("deleteInvestigationNote deletes note by ID", async () => {
    setEngineToken("m4_del_note_token");

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => ({ deleted: true, note_id: 1 }),
    } as Response);

    const { deleteInvestigationNote } = await import("../lib/api");
    const result = await deleteInvestigationNote(1);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/investigations/notes/1",
      expect.objectContaining({ method: "DELETE" })
    );
    expect(result.deleted).toBe(true);
  });

  it("inspectEventForensics retrieves deep event forensics lineage", async () => {
    setEngineToken("m4_forensics_token");

    const mockForensics = {
      event_id: "evt-uuid-1234",
      event: { id: "evt-uuid-1234", host: "srv-01", event_type: "auth" },
      provenance: { raw_message: "Failed password for root", timestamp: "2026-09-30T10:00:00Z" },
      detections: [],
      alerts: [],
      incidents: [],
      entities: ["user:root", "host:srv-01"],
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockForensics,
    } as Response);

    const { inspectEventForensics } = await import("../lib/api");
    const result = await inspectEventForensics("evt-uuid-1234");

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/investigations/events/evt-uuid-1234/inspect",
      expect.objectContaining({ headers: expect.any(Headers) })
    );
    expect(result.event_id).toBe("evt-uuid-1234");
    expect(result.entities).toContain("user:root");
  });

  it("inspectEntityPivot retrieves entity pivot summary", async () => {
    setEngineToken("m4_pivot_token");

    const mockPivot = {
      entity_key: "host:srv-01",
      entity_type: "HOST",
      display_name: "srv-01",
      total_events: 15,
      total_alerts: 2,
      total_incidents: 1,
      associated_hosts: ["srv-01"],
      associated_users: ["root"],
      associated_ips: ["192.168.1.10"],
      associated_processes: ["sshd"],
      related_relationships: [],
      recent_events: [],
      alerts: [],
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockPivot,
    } as Response);

    const { inspectEntityPivot } = await import("../lib/api");
    const result = await inspectEntityPivot("host:srv-01");

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/investigations/entities/host%3Asrv-01/pivot",
      expect.objectContaining({ headers: expect.any(Headers) })
    );
    expect(result.entity_key).toBe("host:srv-01");
    expect(result.associated_users).toContain("root");
  });

  it("executeThreatHunt executes multi-parameter hunting search", async () => {
    setEngineToken("m4_hunt_token");

    const mockHunt = {
      items: [{ id: "evt-01", event_type: "auth", outcome: "failure" }],
      total: 1,
      limit: 50,
      offset: 0,
      query_summary: "event_type = auth",
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockHunt,
    } as Response);

    const { executeThreatHunt } = await import("../lib/api");
    const result = await executeThreatHunt({ event_type: "auth", outcome: "failure" });

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/investigations/hunt",
      expect.objectContaining({
        method: "POST",
        headers: expect.any(Headers),
        body: JSON.stringify({ event_type: "auth", outcome: "failure" }),
      })
    );
    expect(result.items.length).toBe(1);
    expect(result.total).toBe(1);
  });

  it("exportInvestigationReport downloads investigation dossier in markdown", async () => {
    setEngineToken("m4_export_token");

    const mockExport = {
      incident_id: 11,
      format: "markdown",
      content: "# Investigation Dossier",
      filename: "investigation_incident_11.md",
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockExport,
    } as Response);

    const { exportInvestigationReport } = await import("../lib/api");
    const result = await exportInvestigationReport(11, "markdown");

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/investigations/11/export?format=markdown",
      expect.objectContaining({ headers: expect.any(Headers) })
    );
    expect(result.filename).toBe("investigation_incident_11.md");
    expect(result.content).toBe("# Investigation Dossier");
  });
  it("createOrOpenCase sends POST to /cases with incident_id and title", async () => {
    setEngineToken("m55_case_token");
    const mockCase = {
      case_id: 301,
      incident_id: 301,
      title: "Case 301",
      status: "OPEN",
      version: 1,
      owner: "SecAnalyst-1",
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockCase,
    } as Response);

    const { createOrOpenCase } = await import("../lib/api");
    const result = await createOrOpenCase(301, "Case 301");

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/cases",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ Authorization: "Bearer m55_case_token" }),
        body: JSON.stringify({ incident_id: 301, title: "Case 301" }),
      })
    );
    expect(result.case_id).toBe(301);
    expect(result.status).toBe("OPEN");
  });

  it("updateCaseStatus sends state transition request", async () => {
    setEngineToken("m55_state_token");
    const mockUpdatedCase = {
      case_id: 301,
      incident_id: 301,
      status: "ACTIVE",
      version: 2,
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockUpdatedCase,
    } as Response);

    const { updateCaseStatus } = await import("../lib/api");
    const result = await updateCaseStatus(301, "ACTIVE", "Starting investigation");

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/cases/301/state",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ Authorization: "Bearer m55_state_token" }),
        body: JSON.stringify({ target_status: "ACTIVE", reason: "Starting investigation" }),
      })
    );
    expect(result.status).toBe("ACTIVE");
    expect(result.version).toBe(2);
  });

  it("handoffCase transfers ownership and records handoff notes", async () => {
    setEngineToken("m55_handoff_token");
    const mockHandoff = {
      case_id: 301,
      owner: "SecAnalyst-2",
      version: 3,
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockHandoff,
    } as Response);

    const { handoffCase } = await import("../lib/api");
    const result = await handoffCase(301, "SecAnalyst-2", "Shift handoff");

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/cases/301/handoff",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ Authorization: "Bearer m55_handoff_token" }),
        body: JSON.stringify({ new_owner: "SecAnalyst-2", handoff_notes: "Shift handoff" }),
      })
    );
    expect(result.owner).toBe("SecAnalyst-2");
  });

  it("compareCaseReportVersions queries diff endpoint with version parameters", async () => {
    setEngineToken("m55_diff_token");
    const mockDiff = {
      case_id: 301,
      version_a: 1,
      version_b: 2,
      summary_diff: ["+ Added conclusion"],
      facts_added: ["[event:101]"],
      facts_removed: [],
      recommendations_diff: [],
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockDiff,
    } as Response);

    const { compareCaseReportVersions } = await import("../lib/api");
    const result = await compareCaseReportVersions(301, 1, 2);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/cases/301/reports/compare?v1=1&v2=2",
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: "Bearer m55_diff_token" }),
      })
    );
    expect(result.version_a).toBe(1);
    expect(result.version_b).toBe(2);
    expect(result.facts_added).toContain("[event:101]");
  });

  it("fetchCaseAuditLog retrieves immutable audit trail records", async () => {
    setEngineToken("m55_audit_token");
    const mockAudit = [
      { audit_id: 1, case_id: 301, timestamp: "2026-10-02T10:00:00Z", actor: "analyst", action: "CASE_CREATED" },
    ];

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockAudit,
    } as Response);

    const { fetchCaseAuditLog } = await import("../lib/api");
    const result = await fetchCaseAuditLog(301);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/cases/301/audit",
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: "Bearer m55_audit_token" }),
      })
    );
    expect(result.length).toBe(1);
    expect(result[0].action).toBe("CASE_CREATED");
  });

  it("fetchCaseFindings retrieves structured findings and multi-attribute correlations", async () => {
    setEngineToken("m56_findings_token");
    const mockData = {
      case_id: 501,
      findings: [
        {
          finding_id: "fnd-1",
          case_id: 501,
          finding_type: "AUTHENTICATION_FAILURE_BURST",
          title: "Brute Force Pattern",
          description: "Multiple failures",
          epistemic_status: "OBSERVED",
          confidence_basis: "Forensic events",
          source_references: ["[event:101]"],
          related_entities: ["user:deployer"],
          related_alerts: [],
          related_detections: [],
          related_events: ["101"],
          created_at: "2026-10-02T12:00:00Z",
          generated_by: "DETERMINISTIC_CORRELATOR",
        },
      ],
      correlations: [
        {
          correlation_id: "corr-1",
          case_id: 501,
          source_item: "[event:101]",
          target_item: "[alert:11]",
          reasons: ["same host: srv-01"],
          confidence_score: 1.0,
          shared_entities: ["host:srv-01"],
        },
      ],
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockData,
    } as Response);

    const { fetchCaseFindings } = await import("../lib/api");
    const result = await fetchCaseFindings(501);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/cases/501/findings",
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: "Bearer m56_findings_token" }),
      })
    );
    expect(result.case_id).toBe(501);
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].epistemic_status).toBe("OBSERVED");
    expect(result.correlations.length).toBe(1);
  });

  it("fetchCaseTimeline retrieves unified timeline items with provenance", async () => {
    setEngineToken("m56_timeline_token");
    const mockTimeline = [
      {
        item_id: "tl-1",
        case_id: 501,
        timestamp: "2026-10-02T12:00:00Z",
        source_type: "OBSERVED_EVENT",
        title: "Auth Failure",
        summary: "Failed login",
        provenance: "Authoritative event",
        is_authoritative: true,
      },
    ];

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockTimeline,
    } as Response);

    const { fetchCaseTimeline } = await import("../lib/api");
    const result = await fetchCaseTimeline(501);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/cases/501/timeline",
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: "Bearer m56_timeline_token" }),
      })
    );
    expect(result.length).toBe(1);
    expect(result[0].is_authoritative).toBe(true);
  });

  it("fetchCaseEvidenceGaps retrieves missing telemetry gaps", async () => {
    setEngineToken("m56_gap_token");
    const mockGaps = [
      {
        gap_id: "gap-1",
        case_id: 501,
        gap_type: "MISSING_PROCESS_TELEMETRY",
        description: "No process execution data",
        affected_scope: ["srv-01"],
        supporting_context: "Observed auth without subsequent exec logs",
        status: "OPEN",
      },
    ];

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockGaps,
    } as Response);

    const { fetchCaseEvidenceGaps } = await import("../lib/api");
    const result = await fetchCaseEvidenceGaps(501);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/cases/501/evidence-gaps",
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: "Bearer m56_gap_token" }),
      })
    );
    expect(result.length).toBe(1);
    expect(result[0].gap_type).toBe("MISSING_PROCESS_TELEMETRY");
  });

  it("createThreatHuntProposal and executeCaseThreatHunt perform governed threat hunting", async () => {
    setEngineToken("m56_hunt_token");
    const mockProposal = {
      proposal_id: "hunt-prop-1",
      case_id: 501,
      template_id: "search_auth_failures",
      parameters: { username: "deployer" },
      rationale: "Investigate brute-force burst",
      validation_status: "VALID" as const,
      validation_errors: [],
      preview_query_description: "Hunt auth failures for deployer",
      suggested_by: "analyst-1",
      created_at: "2026-10-02T12:05:00Z",
    };

    const mockExecution = {
      case_id: 501,
      proposal_id: "hunt-prop-1",
      template_id: "search_auth_failures",
      parameters: { username: "deployer" },
      executed_by: "analyst-1",
      approved_by: "lead-analyst",
      executed_at: "2026-10-02T12:06:00Z",
      result_status: "MATCHED" as const,
      result_count: 3,
      matched_items: [{ id: "101" }, { id: "102" }, { id: "103" }],
      candidate_findings: [],
    };

    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockProposal,
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockExecution,
      } as Response);

    const { createThreatHuntProposal, executeCaseThreatHunt } = await import("../lib/api");
    const prop = await createThreatHuntProposal(501, "search_auth_failures", { username: "deployer" }, "Investigate");
    expect(prop.validation_status).toBe("VALID");

    const exec = await executeCaseThreatHunt(501, prop, "lead-analyst");
    expect(exec.result_status).toBe("MATCHED");
    expect(exec.result_count).toBe(3);
  });

  it("fetchCaseIntelligenceDossier and generateCaseIntelligenceSynthesis assemble intelligence advisory", async () => {
    setEngineToken("m56_intel_token");
    const mockDossier = {
      case_id: 501,
      incident_id: 500,
      case_title: "APT Case",
      status: "OPEN",
      owner: "analyst-1",
      findings: [],
      correlations: [],
      evidence_gaps: [],
      timeline: [],
      hypotheses_analysis: [],
      attack_path: [],
      mitre_mappings: [],
      generated_at: "2026-10-02T12:00:00Z",
    };

    const mockSynthesis = {
      case_id: 501,
      summary: "Investigation synthesis",
      observed_claims: ["Failed login burst observed"],
      inferred_claims: [],
      unknowns: ["Target binary"],
      evidence_gaps: ["Process telemetry"],
      correlations: [],
      citations: ["[event:101]"],
      suggested_queries: [],
      hypothesis_assessment: {},
      provenance: { containment_mode: "APPLICATION_LEVEL_AI_CONTAINMENT" },
    };

    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockDossier,
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockSynthesis,
      } as Response);

    const { fetchCaseIntelligenceDossier, generateCaseIntelligenceSynthesis } = await import("../lib/api");
    const dossier = await fetchCaseIntelligenceDossier(501);
    expect(dossier.case_id).toBe(501);

    const synthesis = await generateCaseIntelligenceSynthesis(501, "analyst-1");
    expect(synthesis.observed_claims.length).toBe(1);
    expect(synthesis.provenance.containment_mode).toBe("APPLICATION_LEVEL_AI_CONTAINMENT");
  });

  it("M5.7 investigation dossier and finding review workflow", async () => {
    setEngineToken("m57_dossier_token");
    const mockDossier = {
      case_id: 601,
      incident_id: 600,
      case_title: "Dossier Case",
      status: "OPEN",
      owner: "lead-analyst",
      findings: [{ finding_id: "fnd-601-1", review_state: "UNREVIEWED" }],
      review_state_summary: { UNREVIEWED: 1, ACCEPTED: 0 },
      timeline: [],
      evidence_matrix: [],
      evidence_gaps: [],
      provenance_manifest: [],
    };

    const mockReviewUpdate = {
      case_id: 601,
      finding_id: "fnd-601-1",
      review_state: "ACCEPTED",
      analyst_notes: "Validated by analyst",
      reviewed_by: "lead-analyst",
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockDossier,
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockReviewUpdate,
      } as Response);

    const { getInvestigationDossier, updateFindingReview } = await import("../lib/api");
    const dossier = await getInvestigationDossier(601);
    expect(dossier.case_id).toBe(601);
    expect(dossier.findings[0].review_state).toBe("UNREVIEWED");

    const reviewRes = await updateFindingReview(601, "fnd-601-1", {
      review_state: "ACCEPTED",
      analyst_notes: "Validated by analyst",
      reviewer: "lead-analyst",
    });
    expect(reviewRes.review_state).toBe("ACCEPTED");
  });

  it("M5.7 evidence matrix, gap actions, refined timeline, and briefing", async () => {
    setEngineToken("m57_ops_token");
    const mockMatrix = [
      {
        hypothesis_id: "hyp-1",
        statement: "External attacker",
        status: "SUPPORTED",
        supporting_evidence: [],
        contradicting_evidence: [],
        evidence_gaps: [],
      },
    ];

    const mockGapActions = [
      {
        gap_id: "gap-1",
        case_id: 601,
        gap_type: "MISSING_PROCESS_TELEMETRY",
        suggested_action: "Review process logs",
        execution_nature: "ANALYST_CONTROLLED",
      },
    ];

    const mockTimeline = [
      {
        item_id: "tl-1",
        case_id: 601,
        timestamp: "2026-10-02T12:00:00Z",
        source_type: "OBSERVED_EVENT",
        is_authoritative: true,
        epistemic_status: "OBSERVED",
      },
    ];

    const mockBriefing = {
      case_id: 601,
      incident_id: 600,
      case_title: "Case Briefing",
      scope_summary: {},
      observed_metrics: { event_count: 5 },
      key_findings_summary: [],
      correlations_narrative: "Correlated login burst",
      recommended_next_actions: mockGapActions,
      governance_classification: "DFIR_FORENSIC_OBSERVATION",
    };

    const mockProvenance = [
      {
        entry_id: "prov-1",
        section: "Key Findings",
        source_type: "event",
        source_id: "ev-1",
        epistemic_status: "OBSERVED",
        is_authoritative: true,
      },
    ];

    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce({ ok: true, json: async () => mockMatrix } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockGapActions } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockTimeline } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockBriefing } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockProvenance } as Response);

    const {
      getEvidenceMatrix,
      getEvidenceGapActions,
      getRefinedTimeline,
      getCaseBriefing,
      getProvenanceManifest,
    } = await import("../lib/api");

    const matrix = await getEvidenceMatrix(601);
    expect(matrix[0].status).toBe("SUPPORTED");

    const actions = await getEvidenceGapActions(601);
    expect(actions[0].execution_nature).toBe("ANALYST_CONTROLLED");

    const timeline = await getRefinedTimeline(601);
    expect(timeline[0].is_authoritative).toBe(true);

    const briefing = await getCaseBriefing(601);
    expect(briefing.governance_classification).toBe("DFIR_FORENSIC_OBSERVATION");

    const prov = await getProvenanceManifest(601);
    expect(prov[0].is_authoritative).toBe(true);
  });

  it("M5.8 investigation graph, edge evidence, pivots, paths, temporal chain, explanation and export", async () => {
    setEngineToken("m58_graph_token");

    const mockGraph = {
      case_id: 701,
      incident_id: 700,
      nodes: [
        {
          node_id: "host:srv-01",
          node_type: "HOST",
          display_label: "srv-01",
          is_authoritative: true,
          epistemic_status: "OBSERVED",
          degree: 1,
        },
      ],
      edges: [
        {
          edge_id: "edge-1",
          source_node_id: "user:alice",
          target_node_id: "host:srv-01",
          relationship_type: "AUTHENTICATED_TO",
          epistemic_status: "OBSERVED",
          is_authoritative: true,
          corroboration_status: "DIRECT_OBSERVATION",
          evidence_references: [],
          evidence_event_ids: ["ev-101"],
          description: "alice logged in",
          provenance: "auth.log",
        },
      ],
      total_nodes: 1,
      total_edges: 1,
      observed_edges_count: 1,
      inferred_edges_count: 0,
      corroborated_edges_count: 1,
      contradicted_edges_count: 0,
      generated_at: "2026-10-03T12:00:00Z",
    };

    const mockNodeDetail = {
      node: mockGraph.nodes[0],
      connected_edges: mockGraph.edges,
      connected_nodes: [],
    };

    const mockEdgeEvidence = {
      edge: mockGraph.edges[0],
      evidence_references: [],
      evidence_event_ids: ["ev-101"],
      corroboration_status: "DIRECT_OBSERVATION",
      epistemic_status: "OBSERVED",
      is_authoritative: true,
    };

    const mockPivot = {
      entity_key: "srv-01",
      entity_type: "host",
      case_id: 701,
      connected_nodes: [mockGraph.nodes[0]],
      connected_edges: [mockGraph.edges[0]],
      related_alerts_count: 1,
      related_events_count: 5,
      related_findings_count: 1,
      timeline_occurrences_count: 3,
    };

    const mockPath = {
      path_id: "path-1",
      case_id: 701,
      source_node_id: "user:alice",
      target_node_id: "host:srv-01",
      nodes: [mockGraph.nodes[0]],
      edges: [mockGraph.edges[0]],
      total_steps: 1,
      path_nature: "INVESTIGATION_PATH",
      evidence_references_count: 1,
      summary: "Direct authentication step",
    };

    const mockTemporal = {
      case_id: 701,
      steps: [
        {
          step_index: 0,
          timestamp: "2026-10-03T10:00:00Z",
          edge_id: "edge-1",
          source_node_id: "user:alice",
          target_node_id: "host:srv-01",
          relationship_type: "AUTHENTICATED_TO",
          evidence_citation: "[event:ev-101]",
          epistemic_status: "OBSERVED",
        },
      ],
      total_steps: 1,
    };

    const mockExplain = {
      explanation_id: "exp-1",
      case_id: 701,
      target_ref: "edge:edge-1",
      summary: "Alice authenticated directly to host srv-01.",
      evidence_citations: ["[event:ev-101]"],
      epistemic_status: "OBSERVED",
      is_authoritative: false,
      generated_by: "local-ai",
      generated_at: "2026-10-03T12:05:00Z",
    };

    const mockExport = {
      case_id: 701,
      format: "json",
      content: '{"nodes": [], "edges": []}',
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce({ ok: true, json: async () => mockGraph } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockNodeDetail } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockEdgeEvidence } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockPivot } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockPath } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockTemporal } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockExplain } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockExport } as Response);

    const {
      fetchCaseInvestigationGraph,
      fetchCaseGraphNodeDetail,
      fetchCaseGraphEdgeEvidence,
      fetchCaseEntityPivotGraph,
      fetchCaseInvestigationPath,
      fetchCaseGraphTemporalChain,
      explainCaseGraphRelationship,
      exportCaseInvestigationGraph,
    } = await import("../lib/api");

    const graph = await fetchCaseInvestigationGraph(701, { max_nodes: 50, epistemic_status: "OBSERVED" as any });
    expect(graph.total_nodes).toBe(1);
    expect(fetchSpy.mock.calls[0][0]).toContain("/cases/701/graph?");
    expect(fetchSpy.mock.calls[0][0]).toContain("max_nodes=50");
    expect(fetchSpy.mock.calls[0][0]).toContain("epistemic_status=OBSERVED");

    const nodeDetail = await fetchCaseGraphNodeDetail(701, "host:srv-01");
    expect(nodeDetail.node.node_id).toBe("host:srv-01");

    const edgeEvidence = await fetchCaseGraphEdgeEvidence(701, "edge-1");
    expect(edgeEvidence.corroboration_status).toBe("DIRECT_OBSERVATION");

    const pivot = await fetchCaseEntityPivotGraph(701, "host", "srv-01");
    expect(pivot.related_events_count).toBe(5);

    const path = await fetchCaseInvestigationPath(701, "user:alice", "host:srv-01", 3);
    expect(path.path_nature).toBe("INVESTIGATION_PATH");

    const temporal = await fetchCaseGraphTemporalChain(701);
    expect(temporal.total_steps).toBe(1);

    const explain = await explainCaseGraphRelationship(701, { edge_id: "edge-1" });
    expect(explain.is_authoritative).toBe(false);
    expect(explain.epistemic_status).toBe("OBSERVED");

    const exportRes = await exportCaseInvestigationGraph(701, "json");
    expect(exportRes.format).toBe("json");
  });

  it("M5.9 evidence correlation, clusters, sequences, hypotheses, gaps, and workbench", async () => {
    setEngineToken("m59_test_token");

    const mockClusters = {
      case_id: 801,
      clusters: [
        {
          cluster_id: "cluster-801-test",
          case_id: 801,
          title: "Multi-Entity Host Authentication Cluster",
          summary: "Deterministic cluster",
          cluster_type: "ENTITY",
          correlation_reasons: [
            {
              reason_type: "SHARED_ENTITY",
              description: "Shared user alice",
              dimension_value: "user:alice",
              correlation_basis: "Exact entity equality",
            },
          ],
          temporal_bounds: { start_time: "2026-10-04T10:00:00Z", end_time: "2026-10-04T10:05:00Z" },
          participating_entities: ["user:alice", "host:srv-01"],
          evidence_references: [],
          evidence_event_ids: ["evt-1"],
          epistemic_status: "OBSERVED",
          corroboration_status: "CORROBORATED",
          contradictions: [],
          gaps: [],
          created_at: "2026-10-04T10:05:00Z",
        },
      ],
      total_clusters: 1,
    };

    const mockClusterDetail = {
      cluster: mockClusters.clusters[0],
      related_findings: [],
      related_entities: [],
    };

    const mockSequences = {
      case_id: 801,
      sequences: [
        {
          sequence_id: "seq-801-1",
          case_id: 801,
          pattern_name: "Auth -> Execution",
          description: "Login followed by command",
          steps: [],
          total_steps: 1,
          epistemic_status: "OBSERVED",
          supporting_evidence_count: 1,
        },
      ],
      total_sequences: 1,
    };

    const mockHypSupport = {
      hypothesis_id: "hyp-801",
      case_id: 801,
      statement: "Credential compromise",
      support_status: "SUPPORTED BY EVIDENCE",
      supporting_evidence: [],
      contradicting_evidence: [],
      contextual_evidence: [],
      missing_evidence_descriptions: [],
      unresolved_questions: [],
      recommended_governed_queries: [],
    };

    const mockGaps = {
      case_id: 801,
      gaps: [
        {
          gap_id: "gap-801-1",
          case_id: 801,
          gap_type: "EXPECTED_TELEMETRY_MISSING",
          title: "Process tree gap",
          description: "Missing parent process",
          affected_entities: ["process:powershell.exe"],
          affected_hypotheses: [],
          resolution_remedy: "Query host sysmon",
          status: "OPEN",
        },
      ],
      total_gaps: 1,
    };

    const mockFindingsGen = {
      case_id: 801,
      generated_count: 1,
      findings: [{ finding_id: "finding-801-1", title: "Generated Finding" }],
    };

    const mockWorkbench = {
      case_id: 801,
      entity_key: "user:alice",
      entity_type: "user",
      display_name: "alice",
      related_clusters: [],
      related_findings: [],
      related_sequences: [],
      adjacent_graph_entities: ["host:srv-01"],
      evidence_references: [],
      identified_gaps: [],
      mitre_techniques: [],
    };

    const mockExplain = {
      explanation_id: "exp-801-1",
      case_id: 801,
      target_cluster_id: "cluster-801-test",
      summary: "Advisory summary",
      reasoning_explanation: "Records grouped by shared entity user:alice",
      supporting_citations: ["cit-1"],
      identified_unknowns: [],
      epistemic_status: "OBSERVED",
      is_authoritative: false,
      generated_by: "local_ollama_advisory",
      generated_at: "2026-10-04T10:06:00Z",
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce({ ok: true, json: async () => mockClusters } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockClusterDetail } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockSequences } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockHypSupport } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockGaps } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockFindingsGen } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockWorkbench } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => mockExplain } as Response);

    const {
      fetchEvidenceClusters,
      fetchEvidenceClusterDetail,
      fetchBehavioralSequences,
      fetchHypothesisCorrelationSupport,
      fetchCorrelationEvidenceGaps,
      generateFindingsFromClusters,
      fetchEntityWorkbenchDossier,
      explainCorrelationCluster,
    } = await import("../lib/api");

    const clusters = await fetchEvidenceClusters(801, "ENTITY");
    expect(clusters.total_clusters).toBe(1);
    expect(clusters.clusters[0].cluster_type).toBe("ENTITY");

    const clusterDetail = await fetchEvidenceClusterDetail(801, "cluster-801-test");
    expect(clusterDetail.cluster.cluster_id).toBe("cluster-801-test");

    const sequences = await fetchBehavioralSequences(801);
    expect(sequences.total_sequences).toBe(1);

    const hypSupport = await fetchHypothesisCorrelationSupport(801, "hyp-801");
    expect(hypSupport.support_status).toBe("SUPPORTED BY EVIDENCE");

    const gaps = await fetchCorrelationEvidenceGaps(801);
    expect(gaps.total_gaps).toBe(1);
    expect(gaps.gaps[0].gap_type).toBe("EXPECTED_TELEMETRY_MISSING");

    const findingsGen = await generateFindingsFromClusters(801, ["cluster-801-test"]);
    expect(findingsGen.generated_count).toBe(1);

    const workbench = await fetchEntityWorkbenchDossier(801, "user", "alice");
    expect(workbench.entity_key).toBe("user:alice");

    const explanation = await explainCorrelationCluster(801, {
      cluster_id: "cluster-801-test",
      question: "Why correlated?",
    });
    expect(explanation.is_authoritative).toBe(false);
    expect(explanation.generated_by).toBe("local_ollama_advisory");
  });

  // ============================================================================
  // Milestone 5.10 — Temporal Investigation Reconstruction & Campaign Correlation
  // ============================================================================

  it("M5.10 temporal investigation reconstruction, episodes, transitions, review, and export", async () => {
    setEngineToken("m510_token");

    const mockDossier = {
      reconstruction_id: "recon-case-901-test",
      case_id: 901,
      incident_id: 901,
      generated_at: "2026-10-04T12:00:00Z",
      duration_seconds: 300,
      episodes: [
        {
          episode_id: "ep-901-auth",
          case_id: 901,
          episode_type: "AUTHENTICATION_BURST",
          title: "Authentication Burst on host-alpha",
          summary: "Observed auth events",
          start_time: "2026-10-04T12:00:00Z",
          end_time: "2026-10-04T12:05:00Z",
          duration_seconds: 300,
          entities: ["user:alice", "host:alpha"],
          evidence_references: [],
          evidence_event_ids: ["evt-1"],
          epistemic_status: "OBSERVED",
          corroboration_status: "DIRECT_EVIDENCE",
        },
      ],
      transitions: [
        {
          transition_id: "tr-901-1",
          case_id: 901,
          transition_type: "USER_TO_HOST",
          from_entity: "user:alice",
          to_entity: "host:alpha",
          timestamp: "2026-10-04T12:00:00Z",
          reason: "User authenticated to host",
          correlation_basis: "EXPLICIT_RELATIONSHIP",
          evidence_references: [],
          epistemic_status: "OBSERVED",
          review_state: "UNREVIEWED",
        },
      ],
      evidence_chains: [],
      gaps: [
        {
          gap_id: "gap-901-1",
          case_id: 901,
          gap_type: "TIMESTAMP_GAP",
          title: "Temporal Activity Gap",
          description: "Gap between events",
          affected_entities: ["host:alpha"],
          remedy: "Verify logging",
        },
      ],
      multi_host_traces: [],
      continuities: [],
      campaign_correlations: [
        {
          correlation_id: "camp-901-902",
          primary_incident_id: 901,
          related_incident_id: 902,
          related_incident_title: "Secondary breach",
          relationship_reason: "SHARED_ENTITY",
          correlation_status: "POTENTIALLY_RELATED",
          shared_entities: ["user:alice"],
          shared_evidence_count: 1,
          epistemic_status: "INFERRED",
          summary: "Shared alice account",
        },
      ],
      attack_sequences: [
        {
          sequence_id: "seq-901-1",
          case_id: 901,
          name: "Deterministic Reconstruction Sequence",
          description: "Multi-stage progression",
          steps: [],
          total_steps: 1,
          start_time: "2026-10-04T12:00:00Z",
          end_time: "2026-10-04T12:05:00Z",
          duration_seconds: 300,
          epistemic_status: "OBSERVED",
        },
      ],
      mitre_summary: [],
      provenance_hash: "sha256:reconhash901",
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    // 1. fetchTemporalReconstruction
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => mockDossier,
    } as Response);

    // 2. fetchTemporalEpisodes
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ case_id: 901, episodes: mockDossier.episodes, total_episodes: 1 }),
    } as Response);

    // 3. fetchTemporalTransitions
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ case_id: 901, transitions: mockDossier.transitions, total_transitions: 1 }),
    } as Response);

    // 4. fetchTemporalGaps
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ case_id: 901, gaps: mockDossier.gaps, total_gaps: 1 }),
    } as Response);

    // 5. fetchTemporalSequences
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ case_id: 901, sequences: mockDossier.attack_sequences, total_sequences: 1 }),
    } as Response);

    // 6. fetchCampaignCorrelations
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ case_id: 901, correlations: mockDossier.campaign_correlations, total_correlations: 1 }),
    } as Response);

    // 7. reviewTemporalTransition
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        case_id: 901,
        transition_id: "tr-901-1",
        review_state: "ACCEPTED",
        epistemic_status_preserved: true,
      }),
    } as Response);

    // 8. explainTemporalReconstruction
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        explanation_id: "exp-901-1",
        case_id: 901,
        target_id: "recon-case-901-test",
        explanation_text: "Timeline shows observed authentication followed by execution.",
        is_authoritative: false,
        generated_by: "LOCAL_AI_ADVISORY",
        referenced_citations: ["[EVT:evt-1]"],
        epistemic_status: "INFERRED",
        generated_at: "2026-10-04T12:06:00Z",
      }),
    } as Response);

    // 9. exportTemporalReconstruction
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        case_id: 901,
        format: "json",
        content: JSON.stringify(mockDossier),
      }),
    } as Response);

    const {
      fetchTemporalReconstruction,
      fetchTemporalEpisodes,
      fetchTemporalTransitions,
      fetchTemporalGaps,
      fetchTemporalSequences,
      fetchCampaignCorrelations,
      reviewTemporalTransition,
      explainTemporalReconstruction,
      exportTemporalReconstruction,
    } = await import("../lib/api");

    const recon = await fetchTemporalReconstruction(901);
    expect(recon.case_id).toBe(901);
    expect(recon.episodes.length).toBe(1);

    const episodes = await fetchTemporalEpisodes(901, "AUTHENTICATION_BURST");
    expect(episodes.total_episodes).toBe(1);

    const transitions = await fetchTemporalTransitions(901, { epistemic_status: "OBSERVED" });
    expect(transitions.total_transitions).toBe(1);

    const gaps = await fetchTemporalGaps(901);
    expect(gaps.total_gaps).toBe(1);

    const sequences = await fetchTemporalSequences(901);
    expect(sequences.total_sequences).toBe(1);

    const campaigns = await fetchCampaignCorrelations(901);
    expect(campaigns.total_correlations).toBe(1);
    expect(campaigns.correlations[0].correlation_status).toBe("POTENTIALLY_RELATED");

    const review = await reviewTemporalTransition(901, "tr-901-1", "ACCEPTED", "SecAnalyst-1");
    expect(review.review_state).toBe("ACCEPTED");
    expect(review.epistemic_status_preserved).toBe(true);

    const explanation = await explainTemporalReconstruction(901, "recon-case-901-test");
    expect(explanation.is_authoritative).toBe(false);
    expect(explanation.generated_by).toBe("LOCAL_AI_ADVISORY");

    const exported = await exportTemporalReconstruction(901, "json");
    expect(exported.format).toBe("json");
  });

  it("M5.11 Case Assessment API client methods perform bounded authenticated calls", async () => {
    setEngineToken("valid_token");

    const mockAssessment = {
      case_id: 902,
      assessment_id: "asmt-902-v1",
      assessment_version: 1,
      created_at: "2026-10-04T12:00:00Z",
      updated_at: "2026-10-04T12:00:00Z",
      case_state: "OPEN",
      evidence_state: "SUFFICIENT",
      assessment_state: "DRAFT",
      epistemic_summary: { total_findings: 2, observed: 1, inferred: 1, unknown: 0 },
      key_findings: [
        {
          finding_id: "f-1",
          case_id: 902,
          title: "Initial Authentication",
          description: "User logged in",
          epistemic_status: "OBSERVED",
          severity: "MEDIUM",
          evidence_references: ["ev:101"],
          supporting_references: ["ev:101"],
          contradicting_references: [],
          related_entities: ["alice"],
          related_events: ["101"],
          related_incidents: [902],
          related_sequences: [],
          mitre_references: [],
          review_state: "UNREVIEWED",
          provenance: {},
        },
      ],
      supporting_evidence: ["ev:101"],
      contradicting_evidence: [],
      evidence_gaps: [],
      hypotheses: [],
      questions: [],
      evidence_sufficiency: {
        status: "SUFFICIENT",
        rationale: "Complete telemetry",
        existing_evidence: ["ev:101"],
        missing_evidence: [],
        contradicting_evidence: [],
        next_useful_evidence: [],
      },
      attack_sequence_summary: [],
      affected_entities: ["alice"],
      affected_hosts: ["host-1"],
      mitre_summary: [],
      analyst_assessment: "",
      closure_readiness: {
        status: "READY",
        summary: "Case ready for closure",
        blocking_factors: [],
        warnings: [],
        recommendations: [],
      },
      conclusion: {
        statement: "Activity confirmed",
        epistemic_status: "OBSERVED",
        supporting_evidence: ["ev:101"],
        contradicting_evidence: [],
        limitations: [],
        unknowns: [],
      },
      provenance: { fingerprint: "sha256:abc" },
    };

    const mockBriefing = {
      briefing_id: "brf-902-v1",
      case_id: 902,
      assessment_id: "asmt-902-v1",
      sections: { "Case Overview": "Case 902 Overview" },
      briefing_text: "Full briefing text",
      closure_readiness: "READY",
      evidence_sufficiency: "SUFFICIENT",
      generated_at: "2026-10-04T12:00:00Z",
      provenance_hash: "sha256:abc",
    };

    const mockHandoff = {
      handoff_id: "hnd-902-abc",
      case_id: 902,
      created_at: "2026-10-04T12:00:00Z",
      operator: "SecAnalyst-1",
      case_summary: "Handoff summary",
      current_state: "OPEN",
      key_findings: ["Initial Authentication"],
      open_questions: [],
      evidence_gaps: [],
      hypotheses: [],
      affected_entities: ["alice"],
      analyst_assessment: "Analyst note",
      required_next_actions: ["Sign off"],
      report_versions: [1],
      provenance_manifest: {},
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (url: any) => {
      const urlStr = String(url);
      if (urlStr.includes("/assessment/briefing")) {
        return { ok: true, json: async () => mockBriefing } as Response;
      }
      if (urlStr.includes("/assessment/handoff")) {
        return { ok: true, json: async () => mockHandoff } as Response;
      }
      if (urlStr.includes("/assessment/findings/") && urlStr.includes("/review")) {
        return {
          ok: true,
          json: async () => ({
            review_id: "rev-1",
            case_id: 902,
            finding_id: "f-1",
            review_state: "ACCEPTED",
            epistemic_status_preserved: true,
          }),
        } as Response;
      }
      if (urlStr.includes("/assessment/findings")) {
        return {
          ok: true,
          json: async () => ({ case_id: 902, findings: mockAssessment.key_findings, total_findings: 1 }),
        } as Response;
      }
      if (urlStr.includes("/assessment/questions")) {
        return {
          ok: true,
          json: async () => ({ case_id: 902, questions: [], total_questions: 0 }),
        } as Response;
      }
      if (urlStr.includes("/assessment/readiness")) {
        return { ok: true, json: async () => mockAssessment.closure_readiness } as Response;
      }
      if (urlStr.includes("/assessment/gaps")) {
        return { ok: true, json: async () => ({ case_id: 902, evidence_gaps: [], total_gaps: 0 }) } as Response;
      }
      if (urlStr.includes("/assessment/hypotheses")) {
        return { ok: true, json: async () => ({ case_id: 902, hypotheses: [], total_hypotheses: 0 }) } as Response;
      }
      if (urlStr.includes("/assessment/explain")) {
        return {
          ok: true,
          json: async () => ({
            explanation_id: "axp-1",
            case_id: 902,
            target_id: "f-1",
            explanation_text: "Advisory explanation",
            is_authoritative: false,
            generated_by: "LOCAL_AI_ADVISORY",
            referenced_citations: ["ev:101"],
            epistemic_status: "INFERRED",
            generated_at: "2026-10-04T12:00:00Z",
          }),
        } as Response;
      }
      return { ok: true, json: async () => mockAssessment } as Response;
    });

    const {
      getCaseAssessment,
      getCaseFindings,
      reviewCaseFinding,
      getClosureReadiness,
      getInvestigationBriefing,
      getCaseHandoff,
      explainCaseAssessment,
    } = await import("../lib/api");

    const asmt = await getCaseAssessment(902);
    expect(asmt.case_id).toBe(902);
    expect(asmt.evidence_state).toBe("SUFFICIENT");

    const findings = await getCaseFindings(902);
    expect(findings.total_findings).toBe(1);

    const reviewed = await reviewCaseFinding(902, "f-1", "ACCEPTED", "Valid", "SecAnalyst-1");
    expect(reviewed.review_state).toBe("ACCEPTED");
    expect(reviewed.epistemic_status_preserved).toBe(true);

    const readiness = await getClosureReadiness(902);
    expect(readiness.status).toBe("READY");

    const briefing = await getInvestigationBriefing(902);
    expect(briefing.briefing_id).toBe("brf-902-v1");

    const handoff = await getCaseHandoff(902);
    expect(handoff.operator).toBe("SecAnalyst-1");

    const explanation = await explainCaseAssessment(902, "f-1");
    expect(explanation.is_authoritative).toBe(false);
    expect(explanation.generated_by).toBe("LOCAL_AI_ADVISORY");
  });

  it("M6.9 Host Threat Correlation API client methods perform bounded authenticated calls", async () => {
    setEngineToken("m69_token");

    const mockRules = {
      items: [{ id: "sec.reverse_shell_socket", name: "Interactive Shell Outbound Socket Connection" }],
      total: 1,
    };
    const mockAssessment = {
      host: "srv-prod-01",
      incident_id: 101,
      overall_threat_score: 85.0,
      overall_severity: "CRITICAL",
      primary_scenario: "Interactive Reverse Shell & External C2",
      epistemic_confidence: 1.0,
      attack_sequences: [],
      mitre_tactics_observed: ["Command and Control"],
      mitre_techniques_observed: [],
      telemetry_source_diversity: 2,
      summary: "Host Threat Assessment for srv-prod-01",
      node_count: 5,
      edge_count: 4,
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (url: any) => {
      const urlStr = String(url);
      if (urlStr.includes("/detection/host-rules")) {
        return { ok: true, json: async () => mockRules } as Response;
      }
      if (urlStr.includes("/correlation/host-threats/evaluate")) {
        return { ok: true, json: async () => mockAssessment } as Response;
      }
      if (urlStr.includes("/correlation/host-threats/101")) {
        return { ok: true, json: async () => mockAssessment } as Response;
      }
      return { ok: false, statusText: "Not Found" } as Response;
    });

    const {
      fetchHostDetectionRules,
      evaluateHostThreats,
      fetchHostThreatAssessment,
    } = await import("../lib/api");

    const rules = await fetchHostDetectionRules();
    expect(rules.total).toBe(1);

    const evaluated = await evaluateHostThreats("srv-prod-01", 100);
    expect(evaluated.host).toBe("srv-prod-01");
    expect(evaluated.overall_threat_score).toBe(85.0);

    const asmt = await fetchHostThreatAssessment(101);
    expect(asmt.incident_id).toBe(101);
    expect(asmt.primary_scenario).toBe("Interactive Reverse Shell & External C2");
  });

  it("M6.10 Host Validation & Adversary Emulation API client methods perform authenticated calls", async () => {
    setEngineToken("m610_token");

    const mockReport = {
      host: "prod-linux-01",
      platform: "Linux-6.8.0-generic",
      kernel_version: "6.8.0-45-generic",
      live_sources_available: { audit_log: true, proc_net_tcp: true },
      scenario_results: [],
      total_scenarios: 3,
      passed_scenarios: 3,
      overall_passed: true,
      timestamp: "2026-10-06T12:00:00Z",
      summary: "M6.10 Validation: 3/3 passed",
    };

    const mockEmulation = {
      scenario_type: "web_shell_priv_esc_cron",
      scenario_name: "Web Shell to Root Escalation & Cron Persistence",
      host: "prod-linux-01",
      events_generated: 5,
      detections_triggered: 2,
      rule_ids_triggered: ["sec.cron_persistence_tamper"],
      attack_sequences_detected: 1,
      primary_scenario_identified: "Multi-Stage Host Takeover Campaign",
      mitre_tactics: ["Command and Control"],
      mitre_techniques: ["T1071"],
      overall_threat_score: 90.0,
      overall_severity: "CRITICAL",
      epistemic_confidence: 1.0,
      graph_node_count: 5,
      graph_edge_count: 4,
      elapsed_ms: 1.5,
      passed: true,
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (url: any) => {
      const urlStr = String(url);
      if (urlStr.includes("/system/host-validation/emulate")) {
        return { ok: true, json: async () => mockEmulation } as Response;
      }
      if (urlStr.includes("/system/host-validation")) {
        return { ok: true, json: async () => mockReport } as Response;
      }
      return { ok: false, statusText: "Not Found" } as Response;
    });

    const {
      fetchHostValidationReport,
      emulateHostScenario,
    } = await import("../lib/api");

    const report = await fetchHostValidationReport();
    expect(report.host).toBe("prod-linux-01");
    expect(report.overall_passed).toBe(true);

    const emu = await emulateHostScenario("web_shell_priv_esc_cron", "prod-linux-01");
    expect(emu.scenario_type).toBe("web_shell_priv_esc_cron");
    expect(emu.passed).toBe(true);
    expect(emu.overall_threat_score).toBe(90.0);
  });

  it("M7.2: fetchUnifiedTimeline, fetchTimelineReplay, context, bookmarks and export", async () => {
    const {
      fetchUnifiedTimeline,
      fetchTimelineReplay,
      fetchTimelineContext,
      bookmarkTimelineItem,
      removeTimelineBookmark,
      exportUnifiedTimeline,
    } = await import("../lib/api");

    const mockItem = {
      timeline_id: "evt-100",
      case_id: 1,
      timestamp: "2026-03-30T10:00:00Z",
      timestamp_precision: "SECOND",
      host_id: "sec-host-01",
      event_type: "PROCESS_EXEC",
      source_layer: "EVENT",
      source_id: "100",
      entity_refs: ["host:sec-host-01"],
      relationship_refs: [],
      detection_refs: [],
      incident_refs: [1],
      evidence_refs: [],
      epistemic_status: "OBSERVED",
      collection_status: "SOURCE_AVAILABLE",
      display_summary: "Process /usr/bin/bash executed",
      provenance: { source: "test" },
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (url: any, init: any) => {
      const urlStr = String(url);
      if (urlStr.includes("/timeline/unified/export")) {
        return { ok: true, text: async () => JSON.stringify([mockItem]) } as Response;
      }
      if (urlStr.includes("/timeline/unified")) {
        return {
          ok: true,
          json: async () => ({
            total: 1,
            items: [mockItem],
            filter_applied: {},
            deterministic_hash: "mockhash123",
          }),
        } as Response;
      }
      if (urlStr.includes("/timeline/replay")) {
        return {
          ok: true,
          json: async () => ({
            case_id: 1,
            total_frames: 1,
            frames: [{ frame_index: 0, timestamp: "2026-03-30T10:00:00Z", item: mockItem, active_entities: ["host:sec-host-01"], active_hosts: ["sec-host-01"], epistemic_status: "OBSERVED" }],
            session_fingerprint: "sessionhash456",
            deterministic_order: ["evt-100"],
          }),
        } as Response;
      }
      if (urlStr.includes("/timeline/context/evt-100")) {
        return {
          ok: true,
          json: async () => ({
            timeline_id: "evt-100",
            case_id: 1,
            item: mockItem,
            linked_entities: [{ entity_key: "host:sec-host-01" }],
            linked_evidence: [],
            linked_alerts: [],
            traceable_path: [{ level: "TIMELINE_ITEM", id: "evt-100", type: "EVENT", epistemic_status: "OBSERVED" }],
          }),
        } as Response;
      }
      if (urlStr.includes("/timeline/evt-100/bookmark")) {
        if (init?.method === "DELETE") {
          return { ok: true, json: async () => ({ success: true }) } as Response;
        }
        return { ok: true, json: async () => ({ success: true, bookmark_ref_id: "ref-timeline-evt-100" }) } as Response;
      }
      return { ok: false, statusText: "Not Found" } as Response;
    });

    // 1. fetchUnifiedTimeline
    const timeline = await fetchUnifiedTimeline(1, { host: "sec-host-01", limit: 50 });
    expect(timeline.total).toBe(1);
    expect(timeline.items[0].timeline_id).toBe("evt-100");

    // 2. fetchTimelineReplay
    const replay = await fetchTimelineReplay(1);
    expect(replay.total_frames).toBe(1);
    expect(replay.session_fingerprint).toBe("sessionhash456");

    // 3. fetchTimelineContext
    const context = await fetchTimelineContext(1, "evt-100");
    expect(context.item.timeline_id).toBe("evt-100");
    expect(context.traceable_path[0].id).toBe("evt-100");

    // 4. bookmarkTimelineItem
    const bmRes = await bookmarkTimelineItem(1, "evt-100", "Critical anomaly");
    expect(bmRes.success).toBe(true);
    expect(bmRes.bookmark_ref_id).toBe("ref-timeline-evt-100");

    // 5. removeTimelineBookmark
    const unbmRes = await removeTimelineBookmark(1, "evt-100");
    expect(unbmRes.success).toBe(true);

    // 6. exportUnifiedTimeline
    const exportData = await exportUnifiedTimeline(1, "json");
    expect(exportData).toContain("evt-100");
  });

  it("M7.3: fetchCaseCollections, create, add items, workbench, and export", async () => {
    const {
      createCaseCollection,
      fetchCaseCollections,
      fetchCaseCollection,
      addCaseCollectionItem,
      updateCaseCollectionItem,
      removeCaseCollectionItem,
      fetchEvidenceWorkbench,
      exportCaseCollection,
      deleteCaseCollection,
    } = await import("../lib/api");

    const mockCol = {
      collection_id: "col-persistence-123",
      case_id: 1,
      name: "Persistence Evidence",
      description: "Cron and systemd hooks",
      status: "ACTIVE",
      tags: ["persistence"],
      created_at: "2026-03-30T10:00:00Z",
      updated_at: "2026-03-30T10:00:00Z",
      created_by: "SecAnalyst-1",
      items_count: 1,
      items: [
        {
          item_id: "col_item-col-persistence-123-event-101",
          collection_id: "col-persistence-123",
          case_id: 1,
          source_type: "event",
          source_id: "101",
          role: "PERSISTENCE",
          epistemic_status: "OBSERVED",
          collection_status: "SOURCE_AVAILABLE",
          citation_tag: "[event:101]",
          analyst_annotation: "Cron tab created",
          order_index: 1,
          added_at: "2026-03-30T10:05:00Z",
          added_by: "SecAnalyst-1",
          provenance: { source: "test" },
        },
      ],
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (url: any, init: any) => {
      const urlStr = String(url);
      if (urlStr.includes("/evidence/collections/col-persistence-123/export")) {
        return { ok: true, text: async () => JSON.stringify(mockCol) } as Response;
      }
      if (urlStr.includes("/evidence/collections/col-persistence-123/items/col_item-1")) {
        return { ok: true, json: async () => ({ success: true, removed_item_id: "col_item-1" }) } as Response;
      }
      if (urlStr.includes("/evidence/collections/col-persistence-123/items")) {
        return { ok: true, json: async () => mockCol.items[0] } as Response;
      }
      if (urlStr.includes("/evidence/collections/col-persistence-123")) {
        if (init?.method === "DELETE") {
          return { ok: true, json: async () => ({ success: true, deleted_collection_id: "col-persistence-123" }) } as Response;
        }
        return { ok: true, json: async () => mockCol } as Response;
      }
      if (urlStr.includes("/evidence/collections")) {
        if (init?.method === "POST") {
          return { ok: true, json: async () => mockCol } as Response;
        }
        return { ok: true, json: async () => [mockCol] } as Response;
      }
      if (urlStr.includes("/evidence/workbench")) {
        return {
          ok: true,
          json: async () => ({
            case_id: 1,
            total_evidence_count: 1,
            collections: [mockCol],
            items: mockCol.items,
            filter_applied: {},
            deterministic_hash: "hashworkbench123",
          }),
        } as Response;
      }
      return { ok: false, statusText: "Not Found" } as Response;
    });

    // 1. Create collection
    const created = await createCaseCollection(1, { name: "Persistence Evidence", tags: ["persistence"] });
    expect(created.collection_id).toBe("col-persistence-123");

    // 2. List collections
    const cols = await fetchCaseCollections(1);
    expect(cols.length).toBe(1);

    // 3. Fetch single collection
    const col = await fetchCaseCollection(1, "col-persistence-123");
    expect(col.items_count).toBe(1);

    // 4. Add item
    const item = await addCaseCollectionItem(1, "col-persistence-123", {
      source_type: "event",
      source_id: "101",
      role: "PERSISTENCE",
    });
    expect(item.source_id).toBe("101");

    // 5. Workbench
    const wb = await fetchEvidenceWorkbench(1);
    expect(wb.total_evidence_count).toBe(1);
    expect(wb.deterministic_hash).toBe("hashworkbench123");

    // 6. Export
    const exported = await exportCaseCollection(1, "col-persistence-123", "json");
    expect(exported).toContain("col-persistence-123");

    // 7. Remove item
    const remItem = await removeCaseCollectionItem(1, "col-persistence-123", "col_item-1");
    expect(remItem.success).toBe(true);

    // 8. Delete collection
    const delCol = await deleteCaseCollection(1, "col-persistence-123");
    expect(delCol.success).toBe(true);
  });

  it("M7.4: findings & hypothesis workbench API client methods", async () => {
    setEngineToken("m74_token");
    const {
      fetchFindingsWorkbench,
      createCaseFindingM74,
      reviewCaseFindingM74,
      compareHypothesesM74,
      createHypothesisM74,
      exportFindingsWorkbenchM74,
    } = await import("../lib/api");

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    // 1. Fetch workbench
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ case_id: 1, findings: [], hypotheses: [], evidence_gaps: [], total_findings: 0, total_hypotheses: 0, total_gaps: 0 }),
    } as Response);
    const wb = await fetchFindingsWorkbench(1);
    expect(wb.case_id).toBe(1);

    // 2. Create finding
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ finding_id: "FND-1", title: "Test", epistemic_status: "INFERRED", review_status: "UNREVIEWED" }),
    } as Response);
    const fnd = await createCaseFindingM74(1, { title: "Test", statement: "Stmt" });
    expect(fnd.finding_id).toBe("FND-1");

    // 3. Review finding
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ finding_id: "FND-1", review_status: "ACCEPTED", epistemic_status: "INFERRED" }),
    } as Response);
    const rev = await reviewCaseFindingM74(1, "FND-1", "ACCEPTED");
    expect(rev.review_status).toBe("ACCEPTED");

    // 4. Create hypothesis
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ hypothesis_id: "HYP-1", statement: "Hyp Stmt", status: "OPEN" }),
    } as Response);
    const hyp = await createHypothesisM74(1, { statement: "Hyp Stmt" });
    expect(hyp.hypothesis_id).toBe("HYP-1");

    // 5. Compare hypotheses
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ case_id: 1, hypotheses: [{ hypothesis_id: "HYP-1", supporting_count: 2, contradicting_count: 0, gaps_count: 1 }], total_hypotheses: 1 }),
    } as Response);
    const comp = await compareHypothesesM74(1);
    expect(comp.total_hypotheses).toBe(1);

    // 6. Export findings
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      text: async () => '{"case_id": 1, "findings": []}',
    } as Response);
    const exported = await exportFindingsWorkbenchM74(1, "json");
    expect(exported).toContain("findings");
  });

  it("M7.5 Threat Hunting API endpoints execute correctly", async () => {
    const {
      previewThreatHuntM75,
      createThreatHuntProposalM75,
      approveThreatHuntM75,
      executeThreatHuntM75,
      fetchHuntDetailM75,
      fetchCaseHuntsM75,
      pivotThreatHuntEntityM75,
      pivotThreatHuntTemporalM75,
      executeSequenceThreatHuntM75,
      executeIocThreatHuntM75,
      exportThreatHuntM75,
      aiAssistThreatHuntM75,
      convertHuntToFindingM75,
      convertHuntToHypothesisM75,
      convertHuntToCollectionM75,
    } = await import("../lib/api");

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    // 1. Preview
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ case_id: 1, intent: "PROCESS_EXECUTION", validation_status: "VALID", requires_approval: true }),
    } as Response);
    const preview = await previewThreatHuntM75(1, { intent: "PROCESS_EXECUTION" });
    expect(preview.validation_status).toBe("VALID");

    // 2. Create proposal
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ hunt_id: "HNT-101", approval_state: "READY" }),
    } as Response);
    const created = await createThreatHuntProposalM75(1, { question: "Find suspicious logins" });
    expect(created.hunt_id).toBe("HNT-101");

    // 3. Approve
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ hunt_id: "HNT-101", approval_state: "APPROVED" }),
    } as Response);
    const approved = await approveThreatHuntM75(1, "HNT-101");
    expect(approved.approval_state).toBe("APPROVED");

    // 4. Execute
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ hunt_id: "HNT-101", status: "MATCHED", result_count: 2, results: [{ result_id: "R1" }] }),
    } as Response);
    const executed = await executeThreatHuntM75(1, "HNT-101");
    expect(executed.result_count).toBe(2);

    // 5. Entity Pivot
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ hunt_id: "HNT-102", status: "MATCHED", result_count: 1 }),
    } as Response);
    const pivot = await pivotThreatHuntEntityM75(1, "USER", "admin");
    expect(pivot.status).toBe("MATCHED");

    // 6. Temporal Pivot
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ hunt_id: "HNT-103", status: "MATCHED", result_count: 3 }),
    } as Response);
    const temp = await pivotThreatHuntTemporalM75(1, "2026-10-07T10:00:00Z");
    expect(temp.result_count).toBe(3);

    // 7. Sequence
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ sequence_name: "Seq1", matched_steps: 2, total_steps: 2 }),
    } as Response);
    const seq = await executeSequenceThreatHuntM75(1, { case_id: 1, sequence_name: "Seq1", description: "D", steps: [] });
    expect(seq.matched_steps).toBe(2);

    // 8. IOC
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ hunt_id: "HNT-104", status: "MATCHED", result_count: 1 }),
    } as Response);
    const ioc = await executeIocThreatHuntM75(1, "198.51.100.22");
    expect(ioc.result_count).toBe(1);

    // 9. Export
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ hunt_id: "HNT-101", export_content: "{}", fingerprint: "fp-123" }),
    } as Response);
    const exp = await exportThreatHuntM75(1, "HNT-101", "json");
    expect(exp.fingerprint).toBe("fp-123");

    // 10. AI Assist
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ case_id: 1, intent: "AUTHENTICATION_ACTIVITY", question: "SSH Logins" }),
    } as Response);
    const ai = await aiAssistThreatHuntM75(1, "Show SSH logins");
    expect(ai.intent).toBe("AUTHENTICATION_ACTIVITY");

    // 11. Convert to Finding
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ finding_id: "FND-H1", title: "Hunt finding" }),
    } as Response);
    const cFind = await convertHuntToFindingM75(1, { hunt_id: "HNT-101", title: "Hunt finding" });
    expect(cFind.finding_id).toBe("FND-H1");
  });

  it("M7.6 Reporting, Evidence Package and Case Handoff API operations succeed", async () => {
    const {
      createCaseReportM76,
      listCaseReportsM76,
      getCurrentCaseReportM76,
      getCaseReportVersionM76,
      updateCaseReportDraftM76,
      submitCaseReportReviewM76,
      finalizeCaseReportM76,
      compareCaseReportsM76,
      exportCaseReportM76,
      requestAIReportDraftM76,
      createEvidencePackageM76,
      getEvidencePackageM76,
      prepareCaseHandoffM76,
      acknowledgeCaseHandoffM76,
      returnCaseHandoffM76,
      getCurrentCaseHandoffM76,
    } = await import("../lib/api");

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    // 1. Create Report
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        report_id: "rep-101",
        case_id: 1,
        version: 1,
        lifecycle_status: "DRAFT",
        provenance_manifest: { total_references: 5, manifest_blake2b_digest: "digest-1" },
      }),
    } as Response);
    const rep = await createCaseReportM76(1, { title: "Test Report" });
    expect(rep.report_id).toBe("rep-101");
    expect(rep.lifecycle_status).toBe("DRAFT");

    // 2. List Reports
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ case_id: 1, versions: [{ version: 1 }], total_versions: 1 }),
    } as Response);
    const list = await listCaseReportsM76(1);
    expect(list.total_versions).toBe(1);

    // 3. Get Current Report
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ report_id: "rep-101", version: 1 }),
    } as Response);
    const curr = await getCurrentCaseReportM76(1);
    expect(curr.report_id).toBe("rep-101");

    // 4. Update Report Draft
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ report_id: "rep-101", version: 2, lifecycle_status: "DRAFT" }),
    } as Response);
    const updated = await updateCaseReportDraftM76(1, "rep-101", { title: "Updated Report" });
    expect(updated.version).toBe(2);

    // 5. Submit for Review
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ report_id: "rep-101", version: 3, lifecycle_status: "REVIEW_READY" }),
    } as Response);
    const sub = await submitCaseReportReviewM76(1, "rep-101", { review_notes: "Ready" });
    expect(sub.lifecycle_status).toBe("REVIEW_READY");

    // 6. Finalize Report
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ report_id: "rep-101", version: 4, lifecycle_status: "FINALIZED" }),
    } as Response);
    const fin = await finalizeCaseReportM76(1, "rep-101", { reviewed_by: "SecLead-1" });
    expect(fin.lifecycle_status).toBe("FINALIZED");

    // 7. Compare Reports
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ case_id: 1, differences_count: 2, section_diffs: [] }),
    } as Response);
    const cmp = await compareCaseReportsM76(1, 1, 2);
    expect(cmp.differences_count).toBe(2);

    // 8. Export Report
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ case_id: 1, format: "json", fingerprint: "fp-rep" }),
    } as Response);
    const exp = await exportCaseReportM76(1, 1, "json");
    expect(exp.fingerprint).toBe("fp-rep");

    // 9. AI Draft
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ advisory_only: true, content_origin: "AI_GENERATED_DRAFT" }),
    } as Response);
    const ai = await requestAIReportDraftM76(1, { section_to_draft: "executive_summary" });
    expect(ai.advisory_only).toBe(true);

    // 10. Evidence Package
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ manifest: { package_id: "pkg-1", status: "COMPLETED" } }),
    } as Response);
    const pkg = await createEvidencePackageM76(1);
    expect(pkg.manifest.package_id).toBe("pkg-1");

    // 11. Prepare Handoff
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ handoff_id: "hnd-1", status: "READY_FOR_HANDOFF" }),
    } as Response);
    const hnd = await prepareCaseHandoffM76(1, { target_operator: "SecAnalyst-2" });
    expect(hnd.status).toBe("READY_FOR_HANDOFF");

    // 12. Acknowledge Handoff
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ handoff_id: "hnd-1", status: "ACKNOWLEDGED" }),
    } as Response);
    const ack = await acknowledgeCaseHandoffM76(1, "hnd-1");
    expect(ack.status).toBe("ACKNOWLEDGED");

    // 13. Return Handoff
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ handoff_id: "hnd-1", status: "RETURNED_FOR_FOLLOWUP" }),
    } as Response);
    const ret = await returnCaseHandoffM76(1, "hnd-1", { return_reason: "Needs more info" });
    expect(ret.status).toBe("RETURNED_FOR_FOLLOWUP");
  });

  it("M7.7 Case Comparison & Campaign Correlation API operations succeed", async () => {
    setEngineToken("m77_token");

    const {
      createCaseComparison,
      fetchCaseComparison,
      fetchComparisonEntities,
      fetchComparisonTimeline,
      fetchComparisonCorrelations,
      reviewCorrelationCandidate,
      generateComparisonAISummary,
      exportCaseComparison,
    } = await import("../lib/api");

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    // 1. Create Comparison
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        comparison_id: "cmp-1-abc",
        primary_case_id: 1,
        compared_case_ids: [2],
        shared_entities: [{ entity_type: "IP", entity_value: "10.0.0.1" }],
        correlation_candidates: [{ candidate_id: "cand-1", correlation_type: "SHARED_IP" }],
      }),
    } as Response);
    const comp = await createCaseComparison(1, { compared_case_ids: [2] });
    expect(comp.comparison_id).toBe("cmp-1-abc");
    expect(comp.shared_entities.length).toBe(1);

    // 2. Fetch Comparison
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => comp,
    } as Response);
    const fetchedComp = await fetchCaseComparison(1, "cmp-1-abc");
    expect(fetchedComp.comparison_id).toBe("cmp-1-abc");

    // 3. Fetch Entities
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => [{ entity_type: "IP", entity_value: "10.0.0.1" }],
    } as Response);
    const ents = await fetchComparisonEntities(1, "cmp-1-abc");
    expect(ents.length).toBe(1);

    // 4. Fetch Timeline
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ relationship: "OVERLAPPING", delta_seconds: 3600 }),
    } as Response);
    const timeline = await fetchComparisonTimeline(1, "cmp-1-abc");
    expect(timeline.relationship).toBe("OVERLAPPING");

    // 5. Fetch Correlations
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => [{ candidate_id: "cand-1", correlation_type: "SHARED_IP" }],
    } as Response);
    const corrs = await fetchComparisonCorrelations(1, "cmp-1-abc");
    expect(corrs.length).toBe(1);

    // 6. Review Correlation
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        candidate_id: "cand-1",
        analyst_review_status: "CORROBORATED",
        corroboration_nature: "CORROBORATING",
      }),
    } as Response);
    const reviewed = await reviewCorrelationCandidate(1, "cmp-1-abc", "cand-1", {
      status: "CORROBORATED",
      corroboration_nature: "CORROBORATING",
    });
    expect(reviewed.analyst_review_status).toBe("CORROBORATED");

    // 7. AI Summary
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        comparison_id: "cmp-1-abc",
        draft_narrative: "Advisory summary text",
        advisory_only: true,
        content_origin: "AI_GENERATED",
      }),
    } as Response);
    const aiSummary = await generateComparisonAISummary(1, "cmp-1-abc");
    expect(aiSummary.advisory_only).toBe(true);
    expect(aiSummary.content_origin).toBe("AI_GENERATED");

    // 8. Export Comparison
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      text: async () => '{"comparison_id": "cmp-1-abc"}',
    } as Response);
    const exportedText = await exportCaseComparison(1, "cmp-1-abc", "json");
    expect(exportedText).toContain("cmp-1-abc");
  });

  it("M7.8: Case Review, Quality Gates & Closure API operations succeed", async () => {
    setEngineToken("valid_token_m78");

    const {
      fetchCaseReview,
      runCaseReview,
      fetchCaseReviewBlockers,
      acknowledgeCaseReviewBlocker,
      fetchCaseReviewHistory,
      closeCaseWithReview,
      reopenCaseWithReview,
      generateCaseReviewAISummary,
      exportCaseReview,
    } = await import("../lib/api");

    const mockSnapshot = {
      review_id: "rev-1-test",
      case_id: 1,
      case_status: "ACTIVE",
      case_version: 2,
      closure_readiness: "READY_FOR_REVIEW",
      gates: [
        {
          gate_type: "SCOPE",
          title: "Investigation Scope Gate",
          status: "PASS",
          summary: "Scope verified",
          blockers: [],
          details: {},
          recommendations: [],
        },
      ],
      blockers: [
        {
          blocker_id: "blk-1",
          gate_type: "QUESTIONS",
          category: "OPEN_INVESTIGATION_QUESTION",
          description: "Question open",
          severity: "WARNING",
          resolution_state: "UNRESOLVED",
        },
      ],
      coverage: {
        total_references: 5,
        available_references: 5,
        missing_references: 0,
        unresolved_references: 0,
        observed_evidence_count: 5,
        inferred_evidence_count: 0,
        telemetry_gaps_count: 0,
        critical_gaps_count: 0,
      },
      provenance: {
        manifest_id: "man-1",
        case_id: 1,
        closure_readiness: "READY_FOR_REVIEW",
        gates_digest: "abcd",
        blockers_digest: "ef01",
        root_digest: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        generated_at: "2026-10-08T00:00:00Z",
      },
      reviewed_by: "SecAnalyst-1",
      reviewed_at: "2026-10-08T00:00:00Z",
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    // 1. Fetch Review Snapshot
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => mockSnapshot,
    } as Response);
    const snap = await fetchCaseReview(1);
    expect(snap.case_id).toBe(1);
    expect(snap.closure_readiness).toBe("READY_FOR_REVIEW");

    // 2. Run Forensic Review
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => mockSnapshot,
    } as Response);
    const freshSnap = await runCaseReview(1, "Review notes");
    expect(freshSnap.review_id).toBe("rev-1-test");

    // 3. Fetch Blockers
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        case_id: 1,
        total_blockers: 1,
        blockers: mockSnapshot.blockers,
      }),
    } as Response);
    const blkResp = await fetchCaseReviewBlockers(1, "WARNING", true);
    expect(blkResp.total_blockers).toBe(1);

    // 4. Acknowledge Blocker
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        ...mockSnapshot,
        blockers: [{ ...mockSnapshot.blockers[0], resolution_state: "ACKNOWLEDGED" }],
      }),
    } as Response);
    const ackSnap = await acknowledgeCaseReviewBlocker(1, "blk-1", {
      resolution_state: "ACKNOWLEDGED",
      notes: "Acknowledged in test",
    });
    expect(ackSnap.blockers[0].resolution_state).toBe("ACKNOWLEDGED");

    // 5. Fetch Review History
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        case_id: 1,
        total_records: 2,
        records: [{ action: "CASE_REVIEW_EVALUATION" }],
      }),
    } as Response);
    const hist = await fetchCaseReviewHistory(1);
    expect(hist.total_records).toBe(2);

    // 6. Close Case
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        ...mockSnapshot,
        case_status: "CLOSED",
        closure_readiness: "CLOSED",
      }),
    } as Response);
    const closedSnap = await closeCaseWithReview(1, { closure_notes: "Closing test" });
    expect(closedSnap.case_status).toBe("CLOSED");

    // 7. Reopen Case
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        ...mockSnapshot,
        case_status: "ACTIVE",
        closure_readiness: "REOPENED",
      }),
    } as Response);
    const reopenedSnap = await reopenCaseWithReview(1, { reopen_reason: "Reopening test" });
    expect(reopenedSnap.case_status).toBe("ACTIVE");

    // 8. AI Review Summary
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        summary: "Advisory review summary text",
        key_blockers: ["Warning on open question"],
        recommendations: ["Review question"],
        is_authoritative: false,
        advisory_only: true,
      }),
    } as Response);
    const aiResp = await generateCaseReviewAISummary(1);
    expect(aiResp.advisory_only).toBe(true);

    // 9. Export Review
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      text: async () => '{"review_id": "rev-1-test"}',
    } as Response);
    const expText = await exportCaseReview(1, "json");
    expect(expText).toContain("rev-1-test");
  });
});








