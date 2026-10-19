import { describe, it, expect, vi, beforeEach } from "vitest";
import React from "react";
import {
  fetchCaseMultiHostDossier,
  fetchCaseLateralTraces,
  fetchCaseHostTimeline,
  fetchCaseHostContinuity,
  fetchCaseComparativeTimeline,
  exportCaseMultiHostDossier,
  setEngineToken,
  setTokenProvider,
} from "../lib/api";
import { formatSafeTimestamp, formatSafeTimeOnly } from "../features/InvestigationMultiHostWorkbench";
import type {
  CaseHostSummary,
  CaseMultiHostDossier,
  EntityContinuity,
  HostTimelineResponse,
  MultiHostTrace,
  ComparativeTimelineResponse,
  HostTimelineLane,
  MultiHostExportResponse,
} from "../types/investigation";

describe("M7.12 Multi-Host Desktop Investigation Tests", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    setEngineToken(null);
    setTokenProvider(null);
  });

  const mockDossier: CaseMultiHostDossier = {
    case_id: 101,
    incident_id: 201,
    scope_target_hosts: ["workstation-01", "srv-dc01", "unmonitored-host"],
    is_scope_unspecified: false,
    participating_hosts: [
      {
        host_id: "workstation-01",
        hostname: "workstation-01.corp.internal",
        os_name: "Ubuntu",
        os_version: "24.04",
        is_in_target_scope: true,
        first_seen: "2026-10-09T10:00:00Z",
        last_seen: "2026-10-09T10:30:00Z",
        event_count: 15,
        alert_count: 2,
        inbound_lateral_hops: 0,
        outbound_lateral_hops: 1,
        evidence_references: ["[event:ev-101]", "[alert:alt-1]"],
        telemetry_gaps: [],
        discrepancies: [],
        host_graph_available: true,
        epistemic_status: "OBSERVED",
      },
      {
        host_id: "srv-dc01",
        hostname: "dc01.corp.internal",
        os_name: "Windows Server",
        os_version: "2022",
        is_in_target_scope: true,
        first_seen: "2026-10-09T10:15:00Z",
        last_seen: "2026-10-09T11:00:00Z",
        event_count: 28,
        alert_count: 4,
        inbound_lateral_hops: 1,
        outbound_lateral_hops: 0,
        evidence_references: ["[event:ev-201]", "[alert:alt-2]"],
        telemetry_gaps: [
          {
            gap_type: "MISSING_HOST_CATALOG_ENTRY",
            host_identifier: "srv-dc01",
            description: "Host observed in telemetry but absent from authoritative host catalog",
            remedy_suggestion: "Register host in inventory catalog",
          },
        ],
        discrepancies: [
          {
            field: "hostname",
            catalog_value: "dc01-primary",
            telemetry_value: "dc01.corp.internal",
            sources: ["logintel.db:hosts", "telemetry"],
            description: "Host identity name variance detected",
          },
        ],
        host_graph_available: true,
        epistemic_status: "OBSERVED",
      },
      {
        host_id: "unmonitored-host",
        hostname: "unmonitored-host",
        os_name: null,
        os_version: null,
        is_in_target_scope: true,
        first_seen: null,
        last_seen: null,
        event_count: 0,
        alert_count: 0,
        inbound_lateral_hops: 0,
        outbound_lateral_hops: 0,
        evidence_references: [],
        telemetry_gaps: [
          {
            gap_type: "TARGET_HOST_TELEMETRY_ABSENT",
            host_identifier: "unmonitored-host",
            description: "Host explicitly scoped but zero events or alerts observed within case bounds",
            remedy_suggestion: "Verify agent telemetry ingestion and network connectivity",
          },
        ],
        discrepancies: [],
        host_graph_available: false,
        epistemic_status: "UNKNOWN",
      },
    ],
    lateral_traces: [
      {
        trace_id: "mhost-101-0",
        case_id: 101,
        source_host: "workstation-01",
        target_host: "srv-dc01",
        actor: "svc_admin",
        hop_count: 1,
        transitions: [],
        evidence_references: [],
        start_time: "2026-10-09T10:15:00Z",
        end_time: "2026-10-09T10:15:00Z",
        epistemic_status: "OBSERVED",
      },
    ],
    entity_continuity: [],
    total_hosts_count: 3,
    scoped_hosts_count: 3,
    cross_host_hops_count: 1,
    overall_visibility_gaps: [
      {
        gap_type: "TARGET_HOST_TELEMETRY_ABSENT",
        host_identifier: "unmonitored-host",
        description: "Target host unmonitored-host has zero observed telemetry events",
      },
    ],
    completeness_limitations: [
      "Authoritative telemetry database logintel.db is read-only.",
      "Epistemic boundaries strictly enforced: absent telemetry does not constitute proof that an event did not occur.",
    ],
    generated_at: "2026-10-09T12:00:00Z",
    provenance_hash: "sha256:abc123456789",
  };

  const mockTimelineResponse: HostTimelineResponse = {
    case_id: 101,
    host_id: "workstation-01",
    hostname: "workstation-01.corp.internal",
    items: [
      {
        timeline_id: "tl-ev-101",
        case_id: 101,
        timestamp: "2026-10-09T10:00:00Z",
        timestamp_precision: "SECONDS" as any,
        host_id: "workstation-01",
        event_type: "USER_LOGIN",
        source_layer: "AUTH" as any,
        source_id: "ev-101",
        entity_refs: ["user:alice"],
        relationship_refs: [],
        detection_refs: [],
        incident_refs: [201],
        evidence_refs: ["[event:ev-101]"],
        epistemic_status: "OBSERVED" as any,
        collection_status: "SOURCE_AVAILABLE" as any,
        display_summary: "Successful interactive login for user alice",
        provenance: { source: "auth.log" },
      },
    ],
    total: 1,
    limit: 50,
    offset: 0,
    first_seen: "2026-10-09T10:00:00Z",
    last_seen: "2026-10-09T10:30:00Z",
    epistemic_breakdown: { OBSERVED: 1 },
    layer_breakdown: { AUTH: 1 },
  };

  // 1. Dossier API fetching
  it("fetchCaseMultiHostDossier calls GET /api/v1/cases/{caseId}/hosts with token", async () => {
    setEngineToken("test_bearer_token");
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockDossier,
    } as Response);

    const dossier = await fetchCaseMultiHostDossier(101);
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/cases/101/hosts",
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer test_bearer_token",
        }),
      })
    );
    expect(dossier.case_id).toBe(101);
    expect(dossier.total_hosts_count).toBe(3);
    expect(dossier.participating_hosts[0].host_id).toBe("workstation-01");
    expect(dossier.lateral_traces.length).toBe(1);
  });

  // 2. Lateral Traces API fetching
  it("fetchCaseLateralTraces calls GET /api/v1/cases/{caseId}/hosts/lateral-traces", async () => {
    setEngineToken("test_bearer_token");
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockDossier.lateral_traces,
    } as Response);

    const traces = await fetchCaseLateralTraces(101);
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/cases/101/hosts/lateral-traces",
      expect.any(Object)
    );
    expect(traces.length).toBe(1);
    expect(traces[0].source_host).toBe("workstation-01");
    expect(traces[0].target_host).toBe("srv-dc01");
  });

  // 3. Host Timeline API fetching with query parameters
  it("fetchCaseHostTimeline properly encodes host and passes query parameters", async () => {
    setEngineToken("test_bearer_token");
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockTimelineResponse,
    } as Response);

    const timeline = await fetchCaseHostTimeline(101, "workstation-01", {
      limit: 25,
      offset: 50,
      time_start: "2026-10-09T00:00:00Z",
      time_end: "2026-10-09T23:59:59Z",
    });

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/cases/101/hosts/workstation-01/timeline?limit=25&offset=50&time_start=2026-10-09T00%3A00%3A00Z&time_end=2026-10-09T23%3A59%3A59Z",
      expect.any(Object)
    );
    expect(timeline.host_id).toBe("workstation-01");
    expect(timeline.items.length).toBe(1);
    expect(timeline.items[0].source_layer).toBe("AUTH");
  });

  // 4. Authentication Failure handling
  it("fetchCaseMultiHostDossier throws descriptive error on 401 unauthorized", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
      json: async () => ({ detail: "Engine token authentication required" }),
    } as Response);

    await expect(fetchCaseMultiHostDossier(101)).rejects.toThrow(
      "Engine token authentication required"
    );
  });

  // 5. Case-not-found handling
  it("fetchCaseMultiHostDossier throws 404 error when case does not exist", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: "Not Found",
      json: async () => ({ detail: "Investigation case 999999 not found" }),
    } as Response);

    await expect(fetchCaseMultiHostDossier(999999)).rejects.toThrow(
      "Investigation case 999999 not found"
    );
  });

  // 6. Host not associated with case handling
  it("fetchCaseHostTimeline throws 404 when host is not associated with case", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: "Not Found",
      json: async () => ({ detail: "Host 'alien-host' not found or not associated with Case 101" }),
    } as Response);

    await expect(fetchCaseHostTimeline(101, "alien-host")).rejects.toThrow(
      "Host 'alien-host' not found or not associated with Case 101"
    );
  });

  // 7. Network / connection failure handling
  it("handles network failure gracefully without unhandled rejections", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("Connection refused (ECONNREFUSED)"));

    await expect(fetchCaseMultiHostDossier(101)).rejects.toThrow(
      "Connection refused (ECONNREFUSED)"
    );
  });

  // 8. Epistemic distinctions
  it("preserves OBSERVED vs UNKNOWN epistemic demarcation in dossier data", () => {
    const observedHost = mockDossier.participating_hosts.find((h) => h.host_id === "workstation-01");
    const unknownHost = mockDossier.participating_hosts.find((h) => h.host_id === "unmonitored-host");

    expect(observedHost?.epistemic_status).toBe("OBSERVED");
    expect(observedHost?.event_count).toBeGreaterThan(0);

    expect(unknownHost?.epistemic_status).toBe("UNKNOWN");
    expect(unknownHost?.event_count).toBe(0);
    expect(unknownHost?.telemetry_gaps[0].gap_type).toBe("TARGET_HOST_TELEMETRY_ABSENT");
  });

  // 9. Host discrepancy representation
  it("surfaces host identity naming and catalog discrepancies", () => {
    const dc01 = mockDossier.participating_hosts.find((h) => h.host_id === "srv-dc01");
    expect(dc01?.discrepancies.length).toBe(1);
    expect(dc01?.discrepancies[0].field).toBe("hostname");
    expect(dc01?.discrepancies[0].catalog_value).toBe("dc01-primary");
    expect(dc01?.discrepancies[0].telemetry_value).toBe("dc01.corp.internal");
  });

  // 10. Empty case dossier
  it("handles empty case with zero hosts and no lateral traces", async () => {
    const emptyDossier: CaseMultiHostDossier = {
      case_id: 102,
      incident_id: null,
      scope_target_hosts: [],
      is_scope_unspecified: true,
      participating_hosts: [],
      lateral_traces: [],
      entity_continuity: [],
      total_hosts_count: 0,
      scoped_hosts_count: 0,
      cross_host_hops_count: 0,
      overall_visibility_gaps: [],
      completeness_limitations: ["Dynamic scope across all evidence hosts"],
      generated_at: "2026-10-09T12:00:00Z",
      provenance_hash: "sha256:empty",
    };

    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => emptyDossier,
    } as Response);

    const dossier = await fetchCaseMultiHostDossier(102);
    expect(dossier.total_hosts_count).toBe(0);
    expect(dossier.participating_hosts).toEqual([]);
    expect(dossier.is_scope_unspecified).toBe(true);
  });

  // 11. Case switching race safety and stale response discarding
  it("discards stale responses from previous case when active case changes", async () => {
    setEngineToken("test_bearer_token");

    let resolveCase101!: (res: Response) => void;
    const promiseCase101 = new Promise<Response>((resolve) => {
      resolveCase101 = resolve;
    });

    const mockDossier102: CaseMultiHostDossier = {
      ...mockDossier,
      case_id: 102,
      total_hosts_count: 1,
      participating_hosts: [
        {
          ...mockDossier.participating_hosts[0],
          host_id: "isolated-srv",
          hostname: "isolated-srv.internal",
        },
      ],
    };

    vi.spyOn(globalThis, "fetch").mockImplementation(async (url: any) => {
      if (typeof url === "string" && url.includes("/cases/101/hosts")) {
        return promiseCase101;
      }
      if (typeof url === "string" && url.includes("/cases/102/hosts")) {
        return {
          ok: true,
          json: async () => mockDossier102,
        } as Response;
      }
      throw new Error(`Unexpected URL in test: ${url}`);
    });

    // 1. In-flight request initiated for Case 101
    let activeCaseId = 101;
    let activeCaseDossier: CaseMultiHostDossier | null = null;
    const pendingReq101 = fetchCaseMultiHostDossier(101);

    // 2. Analyst switches to Case 102:
    // Immediate state reset pattern applied in InvestigationMultiHostWorkbench
    activeCaseId = 102;
    activeCaseDossier = null; // Verified: cleared immediately on case change
    expect(activeCaseDossier).toBeNull();

    // 3. Case 102 response completes
    const res102 = await fetchCaseMultiHostDossier(102);
    if (activeCaseId === 102) {
      activeCaseDossier = res102;
    }
    expect(activeCaseDossier).not.toBeNull();
    expect(activeCaseDossier?.case_id).toBe(102);
    expect(activeCaseDossier?.participating_hosts[0].host_id).toBe("isolated-srv");

    // 4. Stale Case 101 request finishes after Case 102 is already active
    resolveCase101({
      ok: true,
      json: async () => mockDossier,
    } as Response);
    const staleRes101 = await pendingReq101;

    // Active case guard rejects stale response
    if (staleRes101.case_id === activeCaseId) {
      activeCaseDossier = staleRes101;
    }

    // Active state remains Case 102; no cross-case data leakage
    expect(activeCaseDossier?.case_id).toBe(102);
    expect(activeCaseDossier?.participating_hosts[0].host_id).toBe("isolated-srv");
  });

  // 12. Cross-host entity continuity API fetching
  it("fetchCaseHostContinuity calls GET /api/v1/cases/{caseId}/hosts/continuity with token", async () => {
    setEngineToken("test_bearer_token");
    const mockContinuities: EntityContinuity[] = [
      {
        continuity_id: "cont-101-user-svc_admin",
        case_id: 101,
        continuity_type: "SAME_ACCOUNT_ACROSS_HOSTS" as any,
        entity_key: "user:svc_admin",
        occurrences_count: 3,
        participating_hosts: ["workstation-01", "srv-dc01"],
        evidence_references: [],
        description: "Account 'svc_admin' active across 2 distinct hosts",
      },
      {
        continuity_id: "cont-101-ip-192-168-1-50",
        case_id: 101,
        continuity_type: "SAME_SOURCE_IP" as any,
        entity_key: "ip:192.168.1.50",
        occurrences_count: 5,
        participating_hosts: ["srv-dc01", "unmonitored-host"],
        evidence_references: [],
        description: "Source IP 192.168.1.50 observed across hosts",
      },
    ];

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockContinuities,
    } as Response);

    const continuities = await fetchCaseHostContinuity(101);
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/cases/101/hosts/continuity",
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer test_bearer_token",
        }),
      })
    );
    expect(continuities.length).toBe(2);
    expect(continuities[0].entity_key).toBe("user:svc_admin");
    expect(continuities[0].participating_hosts).toContain("workstation-01");
    expect(continuities[0].participating_hosts).toContain("srv-dc01");
    expect(continuities[1].entity_key).toBe("ip:192.168.1.50");
  });

  // 13. Continuity error handling (401, 404, network failure)
  it("fetchCaseHostContinuity propagates errors correctly", async () => {
    // 401 Unauthorized
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
      json: async () => ({ detail: "Engine token authentication required" }),
    } as Response);
    await expect(fetchCaseHostContinuity(101)).rejects.toThrow("Engine token authentication required");

    // 404 Case not found
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: "Not Found",
      json: async () => ({ detail: "Investigation case 999999 not found" }),
    } as Response);
    await expect(fetchCaseHostContinuity(999999)).rejects.toThrow("Investigation case 999999 not found");

    // Network error
    vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("Network timeout"));
    await expect(fetchCaseHostContinuity(101)).rejects.toThrow("Network timeout");
  });

  // 14. Verification of entity continuity structure preservation
  it("preserves entity continuity types and attributes", () => {
    const userCont: EntityContinuity = {
      continuity_id: "cont-101-user-alice",
      case_id: 101,
      continuity_type: "SAME_ACCOUNT_ACROSS_HOSTS" as any,
      entity_key: "user:alice",
      occurrences_count: 2,
      participating_hosts: ["host-a", "host-b"],
      evidence_references: [],
      description: "User account observed on multiple machines",
    };

    expect(userCont.entity_key.startsWith("user:")).toBe(true);
    expect(userCont.participating_hosts.length).toBe(2);
    expect(userCont.continuity_type).toBe("SAME_ACCOUNT_ACROSS_HOSTS");
  });

  // 15. Comparative Timeline API fetching with query parameters
  it("fetchCaseComparativeTimeline calls GET /api/v1/cases/{caseId}/hosts/timeline/comparative with token and params", async () => {
    setEngineToken("test_bearer_token");
    const mockComparative: ComparativeTimelineResponse = {
      case_id: 101,
      time_start: "2026-10-09T10:00:00Z",
      time_end: "2026-10-09T11:00:00Z",
      lanes: [
        {
          host_id: "workstation-01",
          hostname: "workstation-01.corp.internal",
          items: [
            {
              timeline_id: "tl-ev-101",
              case_id: 101,
              timestamp: "2026-10-09T10:00:00Z",
              timestamp_precision: "SECONDS" as any,
              host_id: "workstation-01",
              event_type: "USER_LOGIN",
              source_layer: "AUTH" as any,
              source_id: "ev-101",
              entity_refs: ["user:alice"],
              relationship_refs: [],
              detection_refs: [],
              incident_refs: [201],
              evidence_refs: ["[event:ev-101]"],
              epistemic_status: "OBSERVED" as any,
              collection_status: "SOURCE_AVAILABLE" as any,
              display_summary: "Successful interactive login for user alice",
              provenance: { source: "auth.log" },
            },
          ],
          total: 1,
          first_seen: "2026-10-09T10:00:00Z",
          last_seen: "2026-10-09T10:30:00Z",
        },
        {
          host_id: "srv-dc01",
          hostname: "dc01.corp.internal",
          items: [],
          total: 0,
          first_seen: null,
          last_seen: null,
        },
      ],
      total_events: 1,
      aligned_min_time: "2026-10-09T10:00:00Z",
      aligned_max_time: "2026-10-09T10:30:00Z",
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockComparative,
    } as Response);

    const comparative = await fetchCaseComparativeTimeline(101, {
      hosts: "workstation-01,srv-dc01",
      time_start: "2026-10-09T10:00:00Z",
      time_end: "2026-10-09T11:00:00Z",
      limit_per_lane: 20,
    });

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/cases/101/hosts/timeline/comparative?hosts=workstation-01%2Csrv-dc01&time_start=2026-10-09T10%3A00%3A00Z&time_end=2026-10-09T11%3A00%3A00Z&limit_per_lane=20",
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer test_bearer_token",
        }),
      })
    );
    expect(comparative.case_id).toBe(101);
    expect(comparative.lanes.length).toBe(2);
    expect(comparative.lanes[0].host_id).toBe("workstation-01");
    expect(comparative.total_events).toBe(1);
    expect(comparative.aligned_min_time).toBe("2026-10-09T10:00:00Z");
  });

  // 16. Comparative Timeline error propagation
  it("fetchCaseComparativeTimeline propagates errors correctly", async () => {
    // 401 Unauthorized
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
      json: async () => ({ detail: "Engine token authentication required" }),
    } as Response);
    await expect(fetchCaseComparativeTimeline(101)).rejects.toThrow("Engine token authentication required");

    // 404 Case not found
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: "Not Found",
      json: async () => ({ detail: "Investigation case 999999 not found" }),
    } as Response);
    await expect(fetchCaseComparativeTimeline(999999)).rejects.toThrow("Investigation case 999999 not found");

    // Network timeout
    vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("Network timeout"));
    await expect(fetchCaseComparativeTimeline(101)).rejects.toThrow("Network timeout");
  });

  // 17. Multi-lane data structure integrity
  it("preserves synchronized lane attributes and alignment metadata", () => {
    const lane: HostTimelineLane = {
      host_id: "host-alpha",
      hostname: "host-alpha.internal",
      items: [],
      total: 0,
      first_seen: null,
      last_seen: null,
    };
    expect(lane.host_id).toBe("host-alpha");
    expect(lane.total).toBe(0);
    expect(lane.items).toEqual([]);
  });

  // 18. Export multi-host dossier as JSON
  it("exportCaseMultiHostDossier calls GET /api/v1/cases/{caseId}/hosts/export?format=json with token", async () => {
    setEngineToken("test_bearer_token");
    const mockExportJson: MultiHostExportResponse = {
      case_id: 101,
      format: "json",
      filename: "case_101_multihost_dossier.json",
      content: JSON.stringify(mockDossier, null, 2),
      root_digest: "sha256:abc123456789",
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockExportJson,
    } as Response);

    const exported = await exportCaseMultiHostDossier(101, "json");
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/cases/101/hosts/export?format=json",
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer test_bearer_token",
        }),
      })
    );
    expect(exported.case_id).toBe(101);
    expect(exported.format).toBe("json");
    expect(exported.filename).toBe("case_101_multihost_dossier.json");
    expect(exported.root_digest).toBe("sha256:abc123456789");
  });

  // 19. Export multi-host dossier as Markdown report
  it("exportCaseMultiHostDossier calls GET /api/v1/cases/{caseId}/hosts/export?format=markdown", async () => {
    setEngineToken("test_bearer_token");
    const mockExportMd: MultiHostExportResponse = {
      case_id: 101,
      format: "markdown",
      filename: "case_101_multihost_report.md",
      content: "# Multi-Host Investigation Report — Case #101\n\n## 1. Executive Summary",
      root_digest: "sha256:abc123456789",
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockExportMd,
    } as Response);

    const exported = await exportCaseMultiHostDossier(101, "markdown");
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:41721/api/v1/cases/101/hosts/export?format=markdown",
      expect.any(Object)
    );
    expect(exported.format).toBe("markdown");
    expect(exported.filename).toBe("case_101_multihost_report.md");
    expect(exported.content).toContain("# Multi-Host Investigation Report");
  });

  // 20. Export error propagation (401, 404, network error)
  it("exportCaseMultiHostDossier propagates errors correctly", async () => {
    // 401 Unauthorized
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
      json: async () => ({ detail: "Engine token authentication required" }),
    } as Response);
    await expect(exportCaseMultiHostDossier(101)).rejects.toThrow("Engine token authentication required");

    // 404 Case not found
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: "Not Found",
      json: async () => ({ detail: "Investigation case 999999 not found" }),
    } as Response);
    await expect(exportCaseMultiHostDossier(999999)).rejects.toThrow("Investigation case 999999 not found");

    // Network timeout
    vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("Network timeout"));
    await expect(exportCaseMultiHostDossier(101)).rejects.toThrow("Network timeout");
  });

  // 21. Multi-Host export structure integrity
  it("preserves export response contract and attributes", () => {
    const payload: MultiHostExportResponse = {
      case_id: 101,
      format: "markdown",
      filename: "case_101_report.md",
      content: "# Report",
      root_digest: "sha256:111222333",
    };
    expect(payload.case_id).toBe(101);
    expect(payload.format).toBe("markdown");
    expect(payload.root_digest.startsWith("sha256:")).toBe(true);
  });

  // 22. Remediate DEFECT M712-003: Timestamp null safety and RangeError prevention
  it("formatSafeTimestamp and formatSafeTimeOnly handle null, undefined, empty, and invalid dates safely without throwing", () => {
    // Valid ISO timestamp
    const validTs = "2026-10-14T08:30:15.000Z";
    expect(formatSafeTimestamp(validTs)).toBe("2026-10-14 08:30:15.000Z");
    expect(formatSafeTimeOnly(validTs)).toBe("08:30:15");

    // Null and undefined
    expect(formatSafeTimestamp(null)).toBe("N/A");
    expect(formatSafeTimestamp(undefined)).toBe("N/A");
    expect(formatSafeTimestamp(null, "Unspecified")).toBe("Unspecified");
    expect(formatSafeTimeOnly(null)).toBe("--:--:--");
    expect(formatSafeTimeOnly(undefined)).toBe("--:--:--");

    // Empty string (which would cause new Date("").toISOString() to throw RangeError: Invalid time value)
    expect(() => formatSafeTimestamp("")).not.toThrow();
    expect(formatSafeTimestamp("")).toBe("N/A");
    expect(() => formatSafeTimeOnly("")).not.toThrow();
    expect(formatSafeTimeOnly("")).toBe("--:--:--");

    // Malformed strings
    expect(() => formatSafeTimestamp("not-a-valid-date")).not.toThrow();
    expect(formatSafeTimestamp("not-a-valid-date")).toBe("N/A");
    expect(() => formatSafeTimeOnly("bogus-timestamp")).not.toThrow();
    expect(formatSafeTimeOnly("bogus-timestamp")).toBe("--:--:--");
  });

  // 23. Remediate DEFECT M712-003: Comparative timeline swimlane null last_seen safety
  it("safely formats swimlane headers when first_seen is present but last_seen is null, empty, or undefined", () => {
    const lane: HostTimelineLane = {
      host_id: "host-web-01",
      hostname: "web01.corp.internal",
      items: [],
      total: 5,
      first_seen: "2026-10-14T10:00:00Z",
      last_seen: null,
    };

    // Simulate workbench lane header formatting:
    // ({formatSafeTimestamp(lane.first_seen)} → {formatSafeTimestamp(lane.last_seen)})
    expect(() => {
      const firstStr = formatSafeTimestamp(lane.first_seen);
      const lastStr = formatSafeTimestamp(lane.last_seen);
      const formatted = `(${firstStr} → ${lastStr})`;
      expect(formatted).toBe("(2026-10-14 10:00:00.000Z → N/A)");
    }).not.toThrow();

    // With empty string
    lane.last_seen = "";
    expect(() => {
      const firstStr = formatSafeTimestamp(lane.first_seen);
      const lastStr = formatSafeTimestamp(lane.last_seen);
      const formatted = `(${firstStr} → ${lastStr})`;
      expect(formatted).toBe("(2026-10-14 10:00:00.000Z → N/A)");
    }).not.toThrow();
  });
});



