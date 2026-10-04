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
              confidence_basis: "Exact entity equality",
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
});



