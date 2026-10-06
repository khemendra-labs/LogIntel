import React, { useState, useEffect, useCallback } from "react";
import {
  EvidenceCollection,
  EvidenceCollectionItem,
  EvidenceCollectionStatus,
  WorkbenchFilterParams,
  EpistemicStatus,
} from "../types/investigation";
import {
  fetchEvidenceWorkbench,
  fetchCaseCollections,
  createCaseCollection,
  updateCaseCollection,
  deleteCaseCollection,
  addCaseCollectionItem,
  removeCaseCollectionItem,
  updateCaseCollectionItem,
  exportCaseCollection,
} from "../lib/api";
import { RefreshIcon, SearchIcon, ExportIcon, FilterIcon, TrashIcon } from "../components/Icons";

interface InvestigationEvidenceWorkbenchProps {
  caseId: number;
  onSelectEventId?: (eventId: string) => void;
  onSelectAlertId?: (alertId: number) => void;
  onSelectEntityKey?: (entityKey: string) => void;
  onJumpToTimeline?: (timelineId?: string) => void;
}

export function InvestigationEvidenceWorkbench({
  caseId,
  onSelectEventId,
  onSelectAlertId,
  onSelectEntityKey,
  onJumpToTimeline,
}: InvestigationEvidenceWorkbenchProps) {
  // Collections & Workbench State
  const [collections, setCollections] = useState<EvidenceCollection[]>([]);
  const [items, setItems] = useState<EvidenceCollectionItem[]>([]);
  const [selectedCollectionId, setSelectedCollectionId] = useState<string | null>(null);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [deterministicHash, setDeterministicHash] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Inspector & Item Selection
  const [selectedItem, setSelectedItem] = useState<EvidenceCollectionItem | null>(null);
  const [editingNote, setEditingNote] = useState<string>("");
  const [editingRole, setEditingRole] = useState<string>("SUPPORTING");
  const [savingItem, setSavingItem] = useState<boolean>(false);

  // Collection Creation Modal / Form State
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newColName, setNewColName] = useState<string>("");
  const [newColDesc, setNewColDesc] = useState<string>("");
  const [newColTags, setNewColTags] = useState<string>("");
  const [creatingCol, setCreatingCol] = useState<boolean>(false);

  // Add Item to Collection Modal
  const [showAddToColModal, setShowAddToColModal] = useState<boolean>(false);
  const [targetColId, setTargetColId] = useState<string>("");
  const [targetRole, setTargetRole] = useState<string>("SUPPORTING");
  const [targetNote, setTargetNote] = useState<string>("");

  // Filters
  const [filterSourceType, setFilterSourceType] = useState<string>("");
  const [filterEpistemic, setFilterEpistemic] = useState<EpistemicStatus | "">("");
  const [filterHost, setFilterHost] = useState<string>("");
  const [filterSearch, setFilterSearch] = useState<string>("");

  // Load Data
  const loadWorkbench = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: WorkbenchFilterParams = {
        collection_id: selectedCollectionId || undefined,
        source_type: filterSourceType || undefined,
        epistemic_status: filterEpistemic || undefined,
        host: filterHost.trim() || undefined,
        search_text: filterSearch.trim() || undefined,
        limit: 500,
        offset: 0,
      };

      const [wbRes, colsRes] = await Promise.all([
        fetchEvidenceWorkbench(caseId, params),
        fetchCaseCollections(caseId),
      ]);

      setCollections(colsRes);
      setItems(wbRes.items);
      setTotalCount(wbRes.total_evidence_count);
      setDeterministicHash(wbRes.deterministic_hash);

      if (wbRes.items.length > 0) {
        setSelectedItem((prev) => {
          if (!prev) return wbRes.items[0];
          const found = wbRes.items.find((it) => it.item_id === prev.item_id);
          return found || wbRes.items[0];
        });
      } else {
        setSelectedItem(null);
      }
    } catch (err: any) {
      setError(`Failed to load evidence workbench: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, [caseId, selectedCollectionId, filterSourceType, filterEpistemic, filterHost, filterSearch]);

  useEffect(() => {
    loadWorkbench();
  }, [loadWorkbench]);

  // Sync editor on item change
  useEffect(() => {
    if (selectedItem) {
      setEditingNote(selectedItem.analyst_annotation || "");
      setEditingRole(selectedItem.role || "SUPPORTING");
    } else {
      setEditingNote("");
      setEditingRole("SUPPORTING");
    }
  }, [selectedItem]);

  // Handlers for Collection Management
  const handleCreateCollection = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newColName.trim()) return;
    setCreatingCol(true);
    setError(null);
    try {
      const tagList = newColTags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
      const created = await createCaseCollection(caseId, {
        name: newColName.trim(),
        description: newColDesc.trim() || undefined,
        tags: tagList,
      });
      setNotice(`Created collection '${created.name}'`);
      setNewColName("");
      setNewColDesc("");
      setNewColTags("");
      setShowCreateModal(false);
      setSelectedCollectionId(created.collection_id);
      loadWorkbench();
      setTimeout(() => setNotice(null), 3500);
    } catch (err: any) {
      setError(`Failed to create collection: ${err.message}`);
    } finally {
      setCreatingCol(false);
    }
  };

  const handleDeleteCollection = async (colId: string) => {
    if (!window.confirm("Are you sure you want to delete this collection? Underlying forensic evidence will remain intact.")) {
      return;
    }
    try {
      await deleteCaseCollection(caseId, colId);
      setNotice("Collection deleted (underlying evidence preserved)");
      if (selectedCollectionId === colId) {
        setSelectedCollectionId(null);
      }
      loadWorkbench();
      setTimeout(() => setNotice(null), 3500);
    } catch (err: any) {
      setError(`Failed to delete collection: ${err.message}`);
    }
  };

  const handleExportCollection = async (colId: string, format: "json" | "csv") => {
    try {
      const data = await exportCaseCollection(caseId, colId, format);
      const blob = new Blob([data], { type: format === "json" ? "application/json" : "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `case_${caseId}_collection_${colId}_export.${format}`;
      a.click();
      URL.revokeObjectURL(url);
      setNotice(`Exported collection as ${format.toUpperCase()}`);
      setTimeout(() => setNotice(null), 3500);
    } catch (err: any) {
      setError(`Export failed: ${err.message}`);
    }
  };

  const handleSaveItemAnnotation = async () => {
    if (!selectedItem || !selectedItem.collection_id) return;
    setSavingItem(true);
    try {
      const updated = await updateCaseCollectionItem(
        caseId,
        selectedItem.collection_id,
        selectedItem.item_id,
        {
          role: editingRole,
          analyst_annotation: editingNote,
        }
      );
      setSelectedItem(updated);
      setItems((prev) => prev.map((it) => (it.item_id === updated.item_id ? updated : it)));
      setNotice("Analyst annotation updated successfully");
      setTimeout(() => setNotice(null), 3500);
    } catch (err: any) {
      setError(`Failed to update annotation: ${err.message}`);
    } finally {
      setSavingItem(false);
    }
  };

  const handleRemoveFromCollection = async (item: EvidenceCollectionItem) => {
    if (!item.collection_id) return;
    try {
      await removeCaseCollectionItem(caseId, item.collection_id, item.item_id);
      setNotice(`Removed reference from collection (underlying evidence intact)`);
      loadWorkbench();
      setTimeout(() => setNotice(null), 3500);
    } catch (err: any) {
      setError(`Failed to remove item: ${err.message}`);
    }
  };

  const handleAddToCollectionSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedItem || !targetColId) return;
    try {
      await addCaseCollectionItem(caseId, targetColId, {
        source_type: selectedItem.source_type,
        source_id: selectedItem.source_id,
        role: targetRole,
        analyst_annotation: targetNote.trim() || undefined,
        citation_tag: selectedItem.citation_tag,
      });
      setNotice(`Added reference to collection`);
      setShowAddToColModal(false);
      setTargetNote("");
      loadWorkbench();
      setTimeout(() => setNotice(null), 3500);
    } catch (err: any) {
      setError(`Failed to add item to collection: ${err.message}`);
    }
  };

  // Badges
  const getEpistemicBadge = (status: EpistemicStatus) => {
    switch (status) {
      case "OBSERVED":
        return <span className="badge badge-notice">OBSERVED</span>;
      case "INFERRED":
        return <span className="badge badge-warning">INFERRED</span>;
      case "UNKNOWN":
      default:
        return <span className="badge badge-neutral">UNKNOWN</span>;
    }
  };

  const activeCol = collections.find((c) => c.collection_id === selectedCollectionId);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px", width: "100%", fontFamily: "var(--font-sans, 'IBM Plex Sans', sans-serif)" }}>
      {/* Header Bar */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "10px",
          padding: "10px 14px",
          background: "var(--bg-surface, #f9f8f5)",
          border: "1px solid var(--border-subtle, #e2e8f0)",
          borderRadius: "2px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--text-primary)" }}>
            M7.3 Logical Evidence Collections & Evidence Workbench
          </span>
          <span style={{ fontSize: "11px", color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>
            Case #{caseId}
          </span>
          <span className="badge badge-neutral" style={{ fontSize: "10px", fontFamily: "var(--font-mono)" }}>
            {totalCount} evidence items
          </span>
          {deterministicHash && (
            <span style={{ fontSize: "10px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }} title="Deterministic Blake2b Hash">
              SHA: {deterministicHash.slice(0, 8)}...
            </span>
          )}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <button className="btn btn-primary" onClick={() => setShowCreateModal(true)} style={{ fontSize: "11px", padding: "4px 10px" }}>
            + New Collection
          </button>
          <button className="btn btn-secondary" onClick={loadWorkbench} disabled={loading} style={{ fontSize: "11px", padding: "4px 8px" }}>
            <RefreshIcon /> {loading ? "Loading..." : "Refresh"}
          </button>
        </div>
      </div>

      {notice && (
        <div style={{ padding: "6px 12px", background: "var(--badge-success-bg, #f0fdf4)", border: "1px solid var(--badge-success-border, #bbf7d0)", color: "var(--badge-success-text, #166534)", fontSize: "11px", borderRadius: "2px" }}>
          {notice}
        </div>
      )}

      {error && (
        <div style={{ padding: "8px 12px", background: "var(--badge-alert-bg, #fef2f2)", border: "1px solid var(--badge-alert-border, #fecaca)", color: "var(--badge-alert-text, #991b1b)", fontSize: "11px", borderRadius: "2px" }}>
          {error}
        </div>
      )}

      {/* Collections Selector Strip */}
      <div
        className="panel"
        style={{
          padding: "8px 12px",
          background: "var(--bg-surface, #ffffff)",
          border: "1px solid var(--border-subtle, #e2e8f0)",
          display: "flex",
          flexDirection: "column",
          gap: "8px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
          <span style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Collections:</span>
          <button
            className={selectedCollectionId === null ? "btn btn-primary" : "btn btn-secondary"}
            onClick={() => setSelectedCollectionId(null)}
            style={{ fontSize: "11px", padding: "3px 8px" }}
          >
            All Evidence ({collections.reduce((acc, c) => acc + c.items_count, 0)})
          </button>

          {collections.map((c) => (
            <button
              key={c.collection_id}
              className={selectedCollectionId === c.collection_id ? "btn btn-primary" : "btn btn-secondary"}
              onClick={() => setSelectedCollectionId(c.collection_id)}
              style={{ fontSize: "11px", padding: "3px 8px", display: "inline-flex", alignItems: "center", gap: "6px" }}
            >
              <span>{c.name}</span>
              <span className="badge badge-neutral" style={{ fontSize: "9px" }}>
                {c.items_count}
              </span>
            </button>
          ))}
        </div>

        {/* Selected Collection Header Details & Actions */}
        {activeCol && (
          <div
            style={{
              padding: "8px 10px",
              background: "var(--bg-subtle, #f8fafc)",
              border: "1px solid var(--border-subtle, #e2e8f0)",
              borderRadius: "2px",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "8px",
            }}
          >
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--text-primary)" }}>{activeCol.name}</span>
                <span className="badge badge-neutral" style={{ fontSize: "9px" }}>{activeCol.status}</span>
                {activeCol.tags.map((t) => (
                  <span key={t} style={{ fontSize: "9px", background: "#e2e8f0", padding: "1px 5px", borderRadius: "2px", color: "#475569" }}>
                    #{t}
                  </span>
                ))}
              </div>
              {activeCol.description && (
                <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px" }}>
                  {activeCol.description}
                </div>
              )}
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <button
                className="btn btn-secondary"
                onClick={() => handleExportCollection(activeCol.collection_id, "json")}
                style={{ fontSize: "10px", padding: "2px 6px" }}
              >
                <ExportIcon /> Export JSON
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => handleExportCollection(activeCol.collection_id, "csv")}
                style={{ fontSize: "10px", padding: "2px 6px" }}
              >
                <ExportIcon /> Export CSV
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => handleDeleteCollection(activeCol.collection_id)}
                style={{ fontSize: "10px", padding: "2px 6px", color: "var(--badge-alert-text)" }}
                title="Delete collection grouping (underlying evidence preserved)"
              >
                <TrashIcon /> Delete
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Filter & Search Bar */}
      <div
        className="panel"
        style={{
          padding: "8px 12px",
          background: "var(--bg-surface, #ffffff)",
          border: "1px solid var(--border-subtle, #e2e8f0)",
          display: "flex",
          flexWrap: "wrap",
          gap: "8px",
          alignItems: "center",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <FilterIcon />
          <span style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Filter:</span>
        </div>

        <select
          value={filterSourceType}
          onChange={(e) => setFilterSourceType(e.target.value)}
          style={{ padding: "3px 6px", fontSize: "11px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
        >
          <option value="">All Sources</option>
          <option value="event">event</option>
          <option value="alert">alert</option>
          <option value="evidence">evidence</option>
          <option value="timeline">timeline</option>
        </select>

        <select
          value={filterEpistemic}
          onChange={(e) => setFilterEpistemic(e.target.value as any)}
          style={{ padding: "3px 6px", fontSize: "11px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
        >
          <option value="">All Epistemic</option>
          <option value="OBSERVED">OBSERVED</option>
          <option value="INFERRED">INFERRED</option>
          <option value="UNKNOWN">UNKNOWN</option>
        </select>

        <input
          type="text"
          placeholder="Host..."
          value={filterHost}
          onChange={(e) => setFilterHost(e.target.value)}
          style={{ padding: "3px 6px", fontSize: "11px", width: "100px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
        />

        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <SearchIcon />
          <input
            type="text"
            placeholder="Search annotation / summary..."
            value={filterSearch}
            onChange={(e) => setFilterSearch(e.target.value)}
            style={{ padding: "3px 6px", fontSize: "11px", width: "180px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
          />
        </div>

        <button
          className="btn btn-secondary"
          onClick={() => {
            setFilterSourceType("");
            setFilterEpistemic("");
            setFilterHost("");
            setFilterSearch("");
          }}
          style={{ fontSize: "10px", padding: "3px 6px" }}
        >
          Reset
        </button>
      </div>

      {/* Main Split Layout: Evidence List (Left) ↔ Detailed Inspector & Cross-Nav (Right) */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 400px", gap: "12px", minHeight: "480px" }}>
        {/* Left Column: Evidence Workbench Items List */}
        <div
          className="panel"
          style={{
            padding: "0",
            background: "var(--bg-surface, #ffffff)",
            border: "1px solid var(--border-subtle, #e2e8f0)",
            overflowY: "auto",
            maxHeight: "560px",
          }}
        >
          {loading && (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)", fontSize: "12px" }}>
              Loading evidence records and collections...
            </div>
          )}

          {!loading && items.length === 0 && (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)", fontSize: "12px" }}>
              No evidence references found for current filter criteria.
            </div>
          )}

          {!loading && items.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column" }}>
              {items.map((it, idx) => {
                const isSelected = selectedItem?.item_id === it.item_id;
                return (
                  <div
                    key={it.item_id}
                    onClick={() => setSelectedItem(it)}
                    style={{
                      padding: "8px 12px",
                      cursor: "pointer",
                      borderBottom: "1px solid var(--border-subtle, #f1f5f9)",
                      borderLeft: isSelected ? "4px solid var(--text-primary, #0f172a)" : "4px solid transparent",
                      background: isSelected ? "var(--bg-selected, #f8fafc)" : "transparent",
                      transition: "background 0.1s ease",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                        <span style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                          #{idx + 1}
                        </span>
                        <span style={{ fontSize: "11px", fontWeight: 700, fontFamily: "var(--font-mono)", color: "var(--text-primary)" }}>
                          {it.citation_tag}
                        </span>
                        <span className="badge badge-neutral" style={{ fontSize: "9px" }}>
                          {it.role}
                        </span>
                        {it.timestamp && (
                          <span style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
                            {it.timestamp}
                          </span>
                        )}
                      </div>

                      <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                        {getEpistemicBadge(it.epistemic_status)}
                      </div>
                    </div>

                    <div style={{ fontSize: "12px", color: "var(--text-primary)", marginBottom: "4px", lineHeight: "1.3" }}>
                      {it.display_summary || `${it.source_type} #${it.source_id}`}
                    </div>

                    {it.analyst_annotation && (
                      <div style={{ fontSize: "11px", color: "var(--text-secondary)", fontStyle: "italic", marginBottom: "4px" }}>
                        &ldquo;{it.analyst_annotation}&rdquo;
                      </div>
                    )}

                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "4px" }}>
                      <span style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                        {it.host_id ? `host: ${it.host_id}` : ""} {it.added_by ? `by: ${it.added_by}` : ""}
                      </span>

                      {selectedCollectionId && it.collection_id && (
                        <button
                          className="btn btn-secondary"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleRemoveFromCollection(it);
                          }}
                          style={{ fontSize: "9px", padding: "1px 5px", color: "var(--badge-alert-text)" }}
                          title="Remove reference from collection (underlying evidence preserved)"
                        >
                          Remove from Collection
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Detailed Inspector & Synchronized Navigation */}
        <div
          className="panel"
          style={{
            padding: "12px 14px",
            background: "var(--bg-surface, #ffffff)",
            border: "1px solid var(--border-subtle, #e2e8f0)",
            overflowY: "auto",
            maxHeight: "560px",
            display: "flex",
            flexDirection: "column",
            gap: "12px",
          }}
        >
          {!selectedItem && (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)", fontSize: "12px" }}>
              Select an evidence item from the workbench to inspect provenance, edit annotations, or jump to timeline/graph.
            </div>
          )}

          {selectedItem && (
            <>
              {/* Top Overview & Action Buttons */}
              <div style={{ borderBottom: "1px solid var(--border-subtle)", paddingBottom: "10px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "4px" }}>
                  <div>
                    <span style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                      {selectedItem.item_id}
                    </span>
                    <h4 style={{ margin: "2px 0 0", fontSize: "13px", fontWeight: 700, color: "var(--text-primary)" }}>
                      {selectedItem.citation_tag}
                    </h4>
                  </div>
                  <button
                    className="btn btn-primary"
                    onClick={() => {
                      setTargetRole(selectedItem.role || "SUPPORTING");
                      setTargetNote(selectedItem.analyst_annotation || "");
                      setShowAddToColModal(true);
                    }}
                    style={{ fontSize: "10px", padding: "3px 8px" }}
                  >
                    + Add to Collection
                  </button>
                </div>

                <div style={{ display: "flex", gap: "6px", alignItems: "center", marginTop: "6px", flexWrap: "wrap" }}>
                  {getEpistemicBadge(selectedItem.epistemic_status)}
                  <span className="badge badge-neutral" style={{ fontSize: "9px" }}>
                    {selectedItem.source_type.toUpperCase()}
                  </span>
                  {selectedItem.host_id && (
                    <span style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
                      Host: <strong>{selectedItem.host_id}</strong>
                    </span>
                  )}
                  {selectedItem.timestamp && (
                    <span style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                      Time: {selectedItem.timestamp}
                    </span>
                  )}
                </div>
              </div>

              {/* Synchronized Cross-Navigation */}
              <div>
                <span style={{ fontSize: "11px", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase" }}>
                  Synchronized Navigation
                </span>
                <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginTop: "6px" }}>
                  {onJumpToTimeline && (
                    <button
                      className="btn btn-secondary"
                      onClick={() => onJumpToTimeline(selectedItem.source_id)}
                      style={{ fontSize: "11px", padding: "4px 8px", textAlign: "left" }}
                    >
                      ▶ Jump to Timeline Focus
                    </button>
                  )}

                  {selectedItem.host_id && onSelectEntityKey && (
                    <button
                      className="btn btn-secondary"
                      onClick={() => onSelectEntityKey(`host:${selectedItem.host_id}`)}
                      style={{ fontSize: "11px", padding: "4px 8px", textAlign: "left" }}
                    >
                      ☊ Pivot to Host Graph (host:{selectedItem.host_id})
                    </button>
                  )}

                  {selectedItem.source_type === "event" && onSelectEventId && (
                    <button
                      className="btn btn-secondary"
                      onClick={() => onSelectEventId(selectedItem.source_id)}
                      style={{ fontSize: "11px", padding: "4px 8px", textAlign: "left" }}
                    >
                      Inspect Source Event #{selectedItem.source_id}
                    </button>
                  )}

                  {selectedItem.source_type === "alert" && onSelectAlertId && (
                    <button
                      className="btn btn-secondary"
                      onClick={() => onSelectAlertId(parseInt(selectedItem.source_id, 10))}
                      style={{ fontSize: "11px", padding: "4px 8px", textAlign: "left" }}
                    >
                      Inspect Source Alert #{selectedItem.source_id}
                    </button>
                  )}
                </div>
              </div>

              {/* Analyst Annotation & Role Editor */}
              {selectedItem.collection_id && (
                <div style={{ borderTop: "1px solid var(--border-subtle)", paddingTop: "10px" }}>
                  <span style={{ fontSize: "11px", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase" }}>
                    Analyst Review & Annotation
                  </span>
                  <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "6px" }}>
                    <div>
                      <label style={{ fontSize: "10px", color: "var(--text-secondary)", display: "block", marginBottom: "2px" }}>
                        Role in Collection:
                      </label>
                      <input
                        type="text"
                        value={editingRole}
                        onChange={(e) => setEditingRole(e.target.value)}
                        style={{ width: "100%", padding: "4px 6px", fontSize: "11px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
                      />
                    </div>
                    <div>
                      <label style={{ fontSize: "10px", color: "var(--text-secondary)", display: "block", marginBottom: "2px" }}>
                        Analyst Note:
                      </label>
                      <textarea
                        rows={3}
                        value={editingNote}
                        onChange={(e) => setEditingNote(e.target.value)}
                        style={{ width: "100%", padding: "4px 6px", fontSize: "11px", border: "1px solid var(--border-subtle)", borderRadius: "2px", resize: "vertical" }}
                      />
                    </div>
                    <button
                      className="btn btn-primary"
                      onClick={handleSaveItemAnnotation}
                      disabled={savingItem}
                      style={{ fontSize: "11px", padding: "4px 8px", alignSelf: "flex-end" }}
                    >
                      {savingItem ? "Saving..." : "Save Annotation"}
                    </button>
                  </div>
                </div>
              )}

              {/* Provenance Manifest */}
              {selectedItem.provenance && Object.keys(selectedItem.provenance).length > 0 && (
                <div style={{ borderTop: "1px solid var(--border-subtle)", paddingTop: "10px" }}>
                  <span style={{ fontSize: "11px", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase" }}>
                    Authoritative Provenance
                  </span>
                  <pre
                    style={{
                      fontSize: "9px",
                      fontFamily: "var(--font-mono)",
                      background: "var(--bg-subtle, #f8fafc)",
                      padding: "6px",
                      borderRadius: "2px",
                      overflowX: "auto",
                      marginTop: "4px",
                      border: "1px solid var(--border-subtle)",
                    }}
                  >
                    {JSON.stringify(selectedItem.provenance, null, 2)}
                  </pre>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {/* Modal: Create Collection */}
      {showCreateModal && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: "rgba(0,0,0,0.4)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
        >
          <div
            className="panel"
            style={{
              width: "420px",
              padding: "16px",
              background: "#ffffff",
              border: "1px solid var(--border-strong)",
              borderRadius: "4px",
              boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
            }}
          >
            <h3 style={{ margin: "0 0 12px", fontSize: "14px", fontWeight: 700 }}>Create Logical Evidence Collection</h3>
            <form onSubmit={handleCreateCollection} style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              <div>
                <label style={{ fontSize: "11px", fontWeight: 600, display: "block", marginBottom: "2px" }}>
                  Name *
                </label>
                <input
                  type="text"
                  placeholder="e.g. Initial Access Vector, Persistence Cron..."
                  value={newColName}
                  onChange={(e) => setNewColName(e.target.value)}
                  style={{ width: "100%", padding: "5px 8px", fontSize: "12px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
                  required
                />
              </div>
              <div>
                <label style={{ fontSize: "11px", fontWeight: 600, display: "block", marginBottom: "2px" }}>
                  Description (Optional)
                </label>
                <textarea
                  rows={2}
                  placeholder="Analyst context and hypothesis..."
                  value={newColDesc}
                  onChange={(e) => setNewColDesc(e.target.value)}
                  style={{ width: "100%", padding: "5px 8px", fontSize: "11px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
                />
              </div>
              <div>
                <label style={{ fontSize: "11px", fontWeight: 600, display: "block", marginBottom: "2px" }}>
                  Tags (Comma-separated)
                </label>
                <input
                  type="text"
                  placeholder="e.g. persistence, cron, privileged"
                  value={newColTags}
                  onChange={(e) => setNewColTags(e.target.value)}
                  style={{ width: "100%", padding: "5px 8px", fontSize: "11px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
                />
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px", marginTop: "8px" }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowCreateModal(false)}
                  style={{ fontSize: "11px", padding: "4px 10px" }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={creatingCol || !newColName.trim()}
                  style={{ fontSize: "11px", padding: "4px 12px" }}
                >
                  {creatingCol ? "Creating..." : "Create Collection"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Add Item to Collection */}
      {showAddToColModal && selectedItem && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: "rgba(0,0,0,0.4)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
        >
          <div
            className="panel"
            style={{
              width: "420px",
              padding: "16px",
              background: "#ffffff",
              border: "1px solid var(--border-strong)",
              borderRadius: "4px",
              boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
            }}
          >
            <h3 style={{ margin: "0 0 12px", fontSize: "14px", fontWeight: 700 }}>
              Add {selectedItem.citation_tag} to Collection
            </h3>
            <form onSubmit={handleAddToCollectionSubmit} style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              <div>
                <label style={{ fontSize: "11px", fontWeight: 600, display: "block", marginBottom: "2px" }}>
                  Select Target Collection *
                </label>
                <select
                  value={targetColId}
                  onChange={(e) => setTargetColId(e.target.value)}
                  style={{ width: "100%", padding: "5px 8px", fontSize: "12px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
                  required
                >
                  <option value="">-- Choose a collection --</option>
                  {collections.map((c) => (
                    <option key={c.collection_id} value={c.collection_id}>
                      {c.name} ({c.items_count} items)
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label style={{ fontSize: "11px", fontWeight: 600, display: "block", marginBottom: "2px" }}>
                  Role in Collection
                </label>
                <input
                  type="text"
                  placeholder="e.g. INITIAL_ACCESS, PERSISTENCE, SUPPORTING"
                  value={targetRole}
                  onChange={(e) => setTargetRole(e.target.value)}
                  style={{ width: "100%", padding: "5px 8px", fontSize: "11px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
                />
              </div>
              <div>
                <label style={{ fontSize: "11px", fontWeight: 600, display: "block", marginBottom: "2px" }}>
                  Analyst Annotation (Optional)
                </label>
                <textarea
                  rows={2}
                  placeholder="Why this evidence belongs in this collection..."
                  value={targetNote}
                  onChange={(e) => setTargetNote(e.target.value)}
                  style={{ width: "100%", padding: "5px 8px", fontSize: "11px", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}
                />
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px", marginTop: "8px" }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowAddToColModal(false)}
                  style={{ fontSize: "11px", padding: "4px 10px" }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={!targetColId}
                  style={{ fontSize: "11px", padding: "4px 12px" }}
                >
                  Add Reference
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
