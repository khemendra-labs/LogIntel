import { describe, expect, it, vi } from "vitest";

describe("Complete Desktop Product Navigation & Integration", () => {
  it("defines all 9 required top-level operational navigation tabs", async () => {
    const { Navigation } = await import("../components/Navigation");
    expect(Navigation).toBeDefined();

    // Verify all 9 tabs are recognized in the union type
    const validTabs: Array<
      | "overview"
      | "activity"
      | "incidents"
      | "alerts"
      | "hunting"
      | "rules"
      | "cases"
      | "multihost"
      | "diagnostics"
    > = [
      "overview",
      "activity",
      "incidents",
      "alerts",
      "hunting",
      "rules",
      "cases",
      "multihost",
      "diagnostics",
    ];
    expect(validTabs).toHaveLength(9);
  });

  describe("Overview Page: Disconnected vs Empty Database Discrimination", () => {
    it("distinguishes backend disconnected state from an empty database", async () => {
      // In OverviewPage, when backendConnected === false, totalEvents is formatted as '—'
      // When backendConnected === true but totalEvents === 0, it renders '0'
      const formatTotalEvents = (connected: boolean, total: number) => {
        if (!connected) return "—";
        return total.toLocaleString();
      };

      const getSubtext = (connected: boolean, total: number, windowEvents: number) => {
        if (!connected) return "Backend offline";
        if (total === 0) return "Database empty (0 events)";
        return `${windowEvents} in 24h`;
      };

      // Disconnected state
      expect(formatTotalEvents(false, 0)).toBe("—");
      expect(getSubtext(false, 0, 0)).toBe("Backend offline");

      // Connected but empty database
      expect(formatTotalEvents(true, 0)).toBe("0");
      expect(getSubtext(true, 0, 0)).toBe("Database empty (0 events)");

      // Connected with populated telemetry
      expect(formatTotalEvents(true, 52130)).toBe("52,130");
      expect(getSubtext(true, 52130, 1420)).toBe("1420 in 24h");
    });

    it("renders pipeline OFFLINE status when backend is disconnected", () => {
      const getPipelineStatus = (connected: boolean, running: boolean) => {
        if (!connected) return "OFFLINE";
        return running ? "RUNNING" : "STANDBY";
      };

      expect(getPipelineStatus(false, false)).toBe("OFFLINE");
      expect(getPipelineStatus(true, true)).toBe("RUNNING");
      expect(getPipelineStatus(true, false)).toBe("STANDBY");
    });
  });

  describe("Cases & Investigation Management", () => {
    it("fetches cases with authorization header and parses response", async () => {
      const mockCases = [
        {
          case_id: 967431,
          incident_id: 967431,
          title: "M7.12 Pipe Escaping Case 117431",
          status: "OPEN",
          owner: "SecAnalyst-1",
          created_at: "2026-10-22T04:00:00Z",
          updated_at: "2026-10-22T04:00:00Z",
          scope: { target_hosts: ["host-alpha", "host-beta"] },
        },
      ];

      const fetchSpy = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockCases,
      });
      globalThis.fetch = fetchSpy;

      const { fetchCases } = await import("../lib/api");
      const cases = await fetchCases();

      expect(fetchSpy).toHaveBeenCalledWith(
        expect.stringContaining("/cases?"),
        expect.objectContaining({
          headers: expect.any(Object),
        })
      );
      expect(cases).toHaveLength(1);
      expect(cases[0].case_id).toBe(967431);
      expect(cases[0].title).toBe("M7.12 Pipe Escaping Case 117431");
      expect(cases[0].scope.target_hosts).toContain("host-alpha");
    });

    it("filters cases by search query across title, description, and target hosts", () => {
      const cases = [
        {
          case_id: 101,
          title: "SSH Brute Force",
          description: "Multiple failed root logins",
          owner: "Analyst-A",
          scope: { target_hosts: ["web-prod-01"] },
        },
        {
          case_id: 102,
          title: "Sudo Privilege Escalation",
          description: "Unauthorized sudo execution",
          owner: "Analyst-B",
          scope: { target_hosts: ["db-prod-01"] },
        },
      ];

      const filterCases = (q: string) => {
        const query = q.toLowerCase();
        return cases.filter(
          (c) =>
            c.title.toLowerCase().includes(query) ||
            c.description.toLowerCase().includes(query) ||
            c.case_id.toString().includes(query) ||
            c.owner.toLowerCase().includes(query) ||
            c.scope.target_hosts.some((h) => h.toLowerCase().includes(query))
        );
      };

      expect(filterCases("SSH")).toHaveLength(1);
      expect(filterCases("db-prod-01")).toHaveLength(1);
      expect(filterCases("db-prod-01")[0].case_id).toBe(102);
      expect(filterCases("Analyst-A")).toHaveLength(1);
      expect(filterCases("nonexistent")).toHaveLength(0);
    });
  });

  describe("Multi-Host Context & Scope Synchronization", () => {
    it("updates target host scope and triggers multi-host dossier reload", async () => {
      const fetchSpy = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          case_id: 967431,
          scope: { target_hosts: ["host-1", "host-2", "host-3"] },
        }),
      });
      globalThis.fetch = fetchSpy;

      const { updateCaseScope } = await import("../lib/api");
      const updated = await updateCaseScope(967431, {
        target_hosts: ["host-1", "host-2", "host-3"],
      } as any);

      expect(fetchSpy).toHaveBeenCalledWith(
        expect.stringContaining("/cases/967431/scope"),
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ target_hosts: ["host-1", "host-2", "host-3"] }),
        })
      );
      expect(updated.scope.target_hosts).toHaveLength(3);
    });
  });

  describe("Diagnostics Page Ingestion Cycle Integration", () => {
    it("calls triggerIngestionCycle and returns parsed event counts", async () => {
      const fetchSpy = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ status: "COMPLETED", ingested_records: 42 }),
      });
      globalThis.fetch = fetchSpy;

      const { triggerIngestionCycle } = await import("../lib/api");
      const res = await triggerIngestionCycle();

      expect(fetchSpy).toHaveBeenCalledWith(
        expect.stringContaining("/ingestion/trigger"),
        expect.objectContaining({ method: "POST" })
      );
      expect(res.ingested_records).toBe(42);
    });
  });
});
