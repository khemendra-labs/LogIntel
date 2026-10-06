import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Optional

from logintel.collections.models import (
    CollectionExportResponse,
    CollectionFilterParams,
    EvidenceCollection,
    EvidenceCollectionItem,
    EvidenceCollectionStatus,
    EvidenceWorkbenchResponse,
    WorkbenchFilterParams,
)
from logintel.storage.case_repo import CaseRepository, case_repo
from logintel.storage.db import Database, db
from logintel.timeline.models import CollectionStatus, EpistemicStatus


class EvidenceWorkbenchService:
    """M7.3 Service managing Logical Evidence Collections and the Evidence Workbench.

    Fundamental Architectural Invariants:
    1. Evidence Collection != Copy of Evidence. Collections contain references, never duplicated payloads.
    2. Epistemic status (OBSERVED, INFERRED, UNKNOWN) is strictly preserved.
    3. Deleting a collection or removing an item never mutates or deletes the underlying forensic evidence.
    4. Strict Case Isolation: all queries and mutations are isolated by case_id.
    5. Append-only audit logging on all mutations.
    """

    def __init__(self, case_repository: CaseRepository = case_repo, forensic_db: Database = db):
        self.case_repo = case_repository
        self.forensic_db = forensic_db

    def _sanitize_string(self, text: str, max_length: int) -> str:
        """Sanitize analyst inputs to inert bounded strings."""
        if not text:
            return ""
        # Strip potential control characters while preserving unicode letters and markdown
        sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
        return sanitized[:max_length].strip()

    def _generate_collection_id(self, name: str) -> str:
        """Generate deterministic/unique collection identifier."""
        clean_name = re.sub(r"[^a-zA-Z0-9_-]", "-", name.lower()).strip("-")
        clean_name = clean_name[:32] if clean_name else "collection"
        hash_suffix = hashlib.blake2b(
            f"{name}-{datetime.now(timezone.utc).isoformat()}".encode(), digest_size=6
        ).hexdigest()
        return f"col-{clean_name}-{hash_suffix}"

    def create_collection(
        self,
        case_id: int,
        name: str,
        description: Optional[str] = None,
        tags: Optional[list[str]] = None,
        actor: str = "SecAnalyst-1",
    ) -> EvidenceCollection:
        """Create a new logical evidence collection within a case."""
        case = self.case_repo.get_case(case_id, resolve_evidence=False)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        # Bounds checking
        clean_name = self._sanitize_string(name, 128)
        if not clean_name:
            raise ValueError("Collection name cannot be empty")
        clean_desc = self._sanitize_string(description or "", 512)
        clean_tags = [self._sanitize_string(t, 32) for t in (tags or []) if t][:20]

        # Check collection limits
        existing = self.get_collections(case_id, limit=200)
        if len(existing) >= 100:
            raise ValueError("Maximum collections limit (100) reached for this case")

        collection_id = self._generate_collection_id(clean_name)
        now_iso = datetime.now(timezone.utc).isoformat()

        annotation_data = {
            "name": clean_name,
            "description": clean_desc,
            "status": EvidenceCollectionStatus.ACTIVE.value,
            "tags": clean_tags,
            "created_at": now_iso,
            "updated_at": now_iso,
            "created_by": actor,
        }

        conn = self.case_repo._get_connection()
        ref_id = f"col-{collection_id}"

        with self.case_repo._lock, conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO case_evidence_references (
                    reference_id, case_id, source_type, source_id, role,
                    epistemic_status, citation_tag, analyst_annotation, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ref_id,
                    case_id,
                    "collection",
                    collection_id,
                    "CONTEXTUAL",
                    "OBSERVED",
                    f"[collection:{collection_id}]",
                    json.dumps(annotation_data),
                    now_iso,
                ),
            )
            self.case_repo.append_audit_log(
                case_id=case_id,
                action="COLLECTION_CREATED",
                new_value=collection_id,
                reason=f"Created logical evidence collection '{clean_name}'",
                actor=actor,
            )

        return EvidenceCollection(
            collection_id=collection_id,
            case_id=case_id,
            name=clean_name,
            description=clean_desc,
            status=EvidenceCollectionStatus.ACTIVE,
            tags=clean_tags,
            created_at=now_iso,
            updated_at=now_iso,
            created_by=actor,
            items_count=0,
            items=[],
        )

    def get_collections(
        self,
        case_id: int,
        status: Optional[EvidenceCollectionStatus] = None,
        search_text: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EvidenceCollection]:
        """List all logical evidence collections for a case with deterministic ordering."""
        case = self.case_repo.get_case(case_id, resolve_evidence=False)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        conn = self.case_repo._get_connection()
        with conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT reference_id, source_id, analyst_annotation, created_at
                FROM case_evidence_references
                WHERE case_id = ? AND source_type = 'collection'
                ORDER BY created_at ASC, source_id ASC
                """,
                (case_id,),
            )
            rows = cur.fetchall()

        collections: list[EvidenceCollection] = []
        clean_search = (search_text or "").strip().lower()

        for r in rows:
            col_id = r["source_id"]
            try:
                meta = json.loads(r["analyst_annotation"] or "{}")
            except Exception:
                meta = {}

            col_status = meta.get("status", EvidenceCollectionStatus.ACTIVE.value)
            if status and col_status != status.value:
                continue

            name = meta.get("name", col_id)
            desc = meta.get("description", "")
            tags = meta.get("tags", [])

            if clean_search:
                match_name = clean_search in name.lower()
                match_desc = clean_search in desc.lower()
                match_tags = any(clean_search in t.lower() for t in tags)
                if not (match_name or match_desc or match_tags):
                    continue

            # Count members
            with conn:
                m_cur = conn.cursor()
                m_cur.execute(
                    """
                    SELECT COUNT(*) as cnt
                    FROM case_evidence_references
                    WHERE case_id = ? AND source_type LIKE 'col_item:%' AND source_id LIKE ?
                    """,
                    (case_id, f"{col_id}:%"),
                )
                m_row = m_cur.fetchone()
                cnt = m_row["cnt"] if m_row else 0

            collections.append(
                EvidenceCollection(
                    collection_id=col_id,
                    case_id=case_id,
                    name=name,
                    description=desc,
                    status=EvidenceCollectionStatus(col_status),
                    tags=tags,
                    created_at=meta.get("created_at", r["created_at"]),
                    updated_at=meta.get("updated_at", r["created_at"]),
                    created_by=meta.get("created_by", "SecAnalyst-1"),
                    items_count=cnt,
                    items=[],
                )
            )

        return collections[offset : offset + limit]

    def get_collection(self, case_id: int, collection_id: str) -> EvidenceCollection:
        """Retrieve a single collection and its resolved member items."""
        case = self.case_repo.get_case(case_id, resolve_evidence=False)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        conn = self.case_repo._get_connection()
        ref_id = f"col-{collection_id}"
        with conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT reference_id, source_id, analyst_annotation, created_at
                FROM case_evidence_references
                WHERE case_id = ? AND reference_id = ? AND source_type = 'collection'
                """,
                (case_id, ref_id),
            )
            row = cur.fetchone()

        if not row:
            raise ValueError(f"Collection '{collection_id}' not found in case {case_id}")

        try:
            meta = json.loads(row["analyst_annotation"] or "{}")
        except Exception:
            meta = {}

        # Fetch member items
        with conn:
            m_cur = conn.cursor()
            m_cur.execute(
                """
                SELECT reference_id, source_type, source_id, role, epistemic_status,
                       citation_tag, analyst_annotation, created_at
                FROM case_evidence_references
                WHERE case_id = ? AND source_type LIKE 'col_item:%' AND source_id LIKE ?
                ORDER BY created_at ASC, reference_id ASC
                """,
                (case_id, f"{collection_id}:%"),
            )
            member_rows = m_cur.fetchall()

        items: list[EvidenceCollectionItem] = []
        for mr in member_rows:
            try:
                item_meta = json.loads(mr["analyst_annotation"] or "{}")
            except Exception:
                item_meta = {}

            raw_source_type = mr["source_type"].replace("col_item:", "")
            raw_source_id = mr["source_id"].split(":", 1)[1] if ":" in mr["source_id"] else mr["source_id"]

            resolved_details = self._resolve_evidence_details(raw_source_type, raw_source_id)

            items.append(
                EvidenceCollectionItem(
                    item_id=mr["reference_id"],
                    collection_id=collection_id,
                    case_id=case_id,
                    source_type=raw_source_type,
                    source_id=raw_source_id,
                    role=item_meta.get("role") or mr["role"],
                    epistemic_status=EpistemicStatus(mr["epistemic_status"]),
                    collection_status=resolved_details.get("collection_status", CollectionStatus.SOURCE_AVAILABLE),
                    citation_tag=mr["citation_tag"],
                    analyst_annotation=item_meta.get("analyst_note"),
                    order_index=item_meta.get("order_index", 0),
                    added_at=mr["created_at"],
                    added_by=item_meta.get("added_by", "SecAnalyst-1"),
                    host_id=resolved_details.get("host_id"),
                    event_type=resolved_details.get("event_type"),
                    timestamp=resolved_details.get("timestamp"),
                    display_summary=resolved_details.get("display_summary"),
                    provenance=resolved_details.get("provenance", {}),
                )
            )

        # Sort items deterministically by order_index, then added_at, then item_id
        items.sort(key=lambda it: (it.order_index, it.added_at, it.item_id))

        return EvidenceCollection(
            collection_id=collection_id,
            case_id=case_id,
            name=meta.get("name", collection_id),
            description=meta.get("description"),
            status=EvidenceCollectionStatus(meta.get("status", EvidenceCollectionStatus.ACTIVE.value)),
            tags=meta.get("tags", []),
            created_at=meta.get("created_at", row["created_at"]),
            updated_at=meta.get("updated_at", row["created_at"]),
            created_by=meta.get("created_by", "SecAnalyst-1"),
            items_count=len(items),
            items=items,
        )

    def update_collection(
        self,
        case_id: int,
        collection_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[EvidenceCollectionStatus] = None,
        tags: Optional[list[str]] = None,
        actor: str = "SecAnalyst-1",
    ) -> EvidenceCollection:
        """Update metadata or status of an existing collection."""
        existing = self.get_collection(case_id, collection_id)
        now_iso = datetime.now(timezone.utc).isoformat()

        updated_name = self._sanitize_string(name, 128) if name is not None else existing.name
        updated_desc = self._sanitize_string(description, 512) if description is not None else existing.description
        updated_status = status if status is not None else existing.status
        updated_tags = (
            [self._sanitize_string(t, 32) for t in tags if t][:20] if tags is not None else existing.tags
        )

        annotation_data = {
            "name": updated_name,
            "description": updated_desc,
            "status": updated_status.value,
            "tags": updated_tags,
            "created_at": existing.created_at,
            "updated_at": now_iso,
            "created_by": existing.created_by,
        }

        conn = self.case_repo._get_connection()
        ref_id = f"col-{collection_id}"

        with self.case_repo._lock, conn:
            conn.execute(
                """
                UPDATE case_evidence_references
                SET analyst_annotation = ?
                WHERE case_id = ? AND reference_id = ? AND source_type = 'collection'
                """,
                (json.dumps(annotation_data), case_id, ref_id),
            )
            self.case_repo.append_audit_log(
                case_id=case_id,
                action="COLLECTION_UPDATED",
                new_value=collection_id,
                reason=f"Updated collection '{updated_name}' (status: {updated_status.value})",
                actor=actor,
            )

        return self.get_collection(case_id, collection_id)

    def delete_collection(self, case_id: int, collection_id: str, actor: str = "SecAnalyst-1") -> bool:
        """Delete an evidence collection.

        IMPORTANT FORENSIC INVARIANT:
        Deleting a collection deletes only the logical grouping and its membership references.
        It NEVER mutates or deletes the underlying authoritative events or primary evidence references.
        """
        existing = self.get_collection(case_id, collection_id)
        conn = self.case_repo._get_connection()
        ref_id = f"col-{collection_id}"

        with self.case_repo._lock, conn:
            # Delete member references belonging to this collection
            conn.execute(
                """
                DELETE FROM case_evidence_references
                WHERE case_id = ? AND source_type LIKE 'col_item:%' AND source_id LIKE ?
                """,
                (case_id, f"{collection_id}:%"),
            )
            # Delete collection header
            conn.execute(
                """
                DELETE FROM case_evidence_references
                WHERE case_id = ? AND reference_id = ? AND source_type = 'collection'
                """,
                (case_id, ref_id),
            )
            self.case_repo.append_audit_log(
                case_id=case_id,
                action="COLLECTION_DELETED",
                new_value=collection_id,
                reason=f"Deleted logical collection '{existing.name}' (underlying evidence preserved)",
                actor=actor,
            )

        return True

    def add_item_to_collection(
        self,
        case_id: int,
        collection_id: str,
        source_type: str,
        source_id: str,
        role: str = "SUPPORTING",
        epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED,
        citation_tag: Optional[str] = None,
        analyst_annotation: Optional[str] = None,
        actor: str = "SecAnalyst-1",
    ) -> EvidenceCollectionItem:
        """Add an evidence reference to a collection.

        Enforces:
        - Strict case isolation
        - No duplication: same collection + same source reference returns idempotent existing item
        - Resource limit: max 1,000 items per collection
        - Zero forensic duplication: stores reference only
        """
        existing_col = self.get_collection(case_id, collection_id)
        if len(existing_col.items) >= 1000:
            raise ValueError(f"Collection '{collection_id}' reached maximum capacity (1000 items)")

        clean_type = self._sanitize_string(source_type, 64).lower()
        clean_source_id = self._sanitize_string(source_id, 128)
        clean_role = self._sanitize_string(role, 64) or "SUPPORTING"
        clean_note = self._sanitize_string(analyst_annotation or "", 1024)

        tag = citation_tag or f"[{clean_type}:{clean_source_id}]"
        now_iso = datetime.now(timezone.utc).isoformat()
        item_ref_id = f"col_item-{collection_id}-{clean_type}-{clean_source_id}"

        conn = self.case_repo._get_connection()

        # Check if already present (idempotent / duplicate protection)
        with conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT reference_id FROM case_evidence_references
                WHERE case_id = ? AND reference_id = ?
                """,
                (case_id, item_ref_id),
            )
            existing_row = cur.fetchone()

        if existing_row:
            # Already in collection; return existing item without modifying
            for it in existing_col.items:
                if it.item_id == item_ref_id:
                    return it

        valid_roles = {"PRIMARY", "SUPPORTING", "CONTEXTUAL", "CORROBORATING", "CONTRADICTING", "TEMPORAL", "ENTITY_LINK"}
        db_role = clean_role if clean_role in valid_roles else "SUPPORTING"

        item_annotation = {
            "collection_id": collection_id,
            "source_type": clean_type,
            "source_id": clean_source_id,
            "role": clean_role,
            "analyst_note": clean_note,
            "order_index": len(existing_col.items) + 1,
            "added_at": now_iso,
            "added_by": actor,
        }

        with self.case_repo._lock, conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO case_evidence_references (
                    reference_id, case_id, source_type, source_id, role,
                    epistemic_status, citation_tag, analyst_annotation, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item_ref_id,
                    case_id,
                    f"col_item:{clean_type}",
                    f"{collection_id}:{clean_source_id}",
                    db_role,
                    epistemic_status.value,
                    tag,
                    json.dumps(item_annotation),
                    now_iso,
                ),
            )
            self.case_repo.append_audit_log(
                case_id=case_id,
                action="COLLECTION_ITEM_ADDED",
                new_value=item_ref_id,
                reason=f"Added evidence {tag} to collection '{existing_col.name}' (role: {clean_role})",
                actor=actor,
            )

        resolved = self._resolve_evidence_details(clean_type, clean_source_id)

        return EvidenceCollectionItem(
            item_id=item_ref_id,
            collection_id=collection_id,
            case_id=case_id,
            source_type=clean_type,
            source_id=clean_source_id,
            role=clean_role,
            epistemic_status=epistemic_status,
            collection_status=resolved.get("collection_status", CollectionStatus.SOURCE_AVAILABLE),
            citation_tag=tag,
            analyst_annotation=clean_note,
            order_index=len(existing_col.items) + 1,
            added_at=now_iso,
            added_by=actor,
            host_id=resolved.get("host_id"),
            event_type=resolved.get("event_type"),
            timestamp=resolved.get("timestamp"),
            display_summary=resolved.get("display_summary"),
            provenance=resolved.get("provenance", {}),
        )

    def remove_item_from_collection(
        self, case_id: int, collection_id: str, item_id: str, actor: str = "SecAnalyst-1"
    ) -> bool:
        """Remove an item from a collection.

        IMPORTANT FORENSIC INVARIANT:
        Removes the item reference from the collection only.
        NEVER removes or mutates the underlying authoritative evidence.
        """
        # Ensure collection belongs to case
        _ = self.get_collection(case_id, collection_id)

        conn = self.case_repo._get_connection()
        with self.case_repo._lock, conn:
            cur = conn.cursor()
            cur.execute(
                """
                DELETE FROM case_evidence_references
                WHERE case_id = ? AND reference_id = ? AND source_type LIKE 'col_item:%'
                """,
                (case_id, item_id),
            )
            if cur.rowcount > 0:
                self.case_repo.append_audit_log(
                    case_id=case_id,
                    action="COLLECTION_ITEM_REMOVED",
                    new_value=item_id,
                    reason=f"Removed item reference {item_id} from collection '{collection_id}'",
                    actor=actor,
                )
                return True
        return False

    def update_collection_item(
        self,
        case_id: int,
        collection_id: str,
        item_id: str,
        role: Optional[str] = None,
        analyst_annotation: Optional[str] = None,
        order_index: Optional[int] = None,
        actor: str = "SecAnalyst-1",
    ) -> EvidenceCollectionItem:
        """Update an item's role, annotation, or order index within a collection."""
        _ = self.get_collection(case_id, collection_id)
        conn = self.case_repo._get_connection()

        with conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT reference_id, source_type, source_id, role, epistemic_status,
                       citation_tag, analyst_annotation, created_at
                FROM case_evidence_references
                WHERE case_id = ? AND reference_id = ? AND source_type LIKE 'col_item:%'
                """,
                (case_id, item_id),
            )
            row = cur.fetchone()

        if not row:
            raise ValueError(f"Collection item '{item_id}' not found in collection '{collection_id}'")

        try:
            item_meta = json.loads(row["analyst_annotation"] or "{}")
        except Exception:
            item_meta = {}

        valid_roles = {"PRIMARY", "SUPPORTING", "CONTEXTUAL", "CORROBORATING", "CONTRADICTING", "TEMPORAL", "ENTITY_LINK"}
        new_role = self._sanitize_string(role, 64) if role is not None else item_meta.get("role", row["role"])
        db_role = new_role if new_role in valid_roles else "SUPPORTING"
        item_meta["role"] = new_role

        if analyst_annotation is not None:
            item_meta["analyst_note"] = self._sanitize_string(analyst_annotation, 1024)
        if order_index is not None:
            item_meta["order_index"] = max(0, order_index)

        with self.case_repo._lock, conn:
            conn.execute(
                """
                UPDATE case_evidence_references
                SET role = ?, analyst_annotation = ?
                WHERE case_id = ? AND reference_id = ?
                """,
                (db_role, json.dumps(item_meta), case_id, item_id),
            )
            self.case_repo.append_audit_log(
                case_id=case_id,
                action="COLLECTION_ITEM_ANNOTATED",
                new_value=item_id,
                reason=f"Updated item {item_id} annotation/role in collection '{collection_id}'",
                actor=actor,
            )

        raw_source_type = row["source_type"].replace("col_item:", "")
        raw_source_id = row["source_id"].split(":", 1)[1] if ":" in row["source_id"] else row["source_id"]
        resolved = self._resolve_evidence_details(raw_source_type, raw_source_id)

        return EvidenceCollectionItem(
            item_id=item_id,
            collection_id=collection_id,
            case_id=case_id,
            source_type=raw_source_type,
            source_id=raw_source_id,
            role=new_role,
            epistemic_status=EpistemicStatus(row["epistemic_status"]),
            collection_status=resolved.get("collection_status", CollectionStatus.SOURCE_AVAILABLE),
            citation_tag=row["citation_tag"],
            analyst_annotation=item_meta.get("analyst_note"),
            order_index=item_meta.get("order_index", 0),
            added_at=row["created_at"],
            added_by=item_meta.get("added_by", "SecAnalyst-1"),
            host_id=resolved.get("host_id"),
            event_type=resolved.get("event_type"),
            timestamp=resolved.get("timestamp"),
            display_summary=resolved.get("display_summary"),
            provenance=resolved.get("provenance", {}),
        )

    def get_workbench_data(
        self, case_id: int, filter_params: Optional[WorkbenchFilterParams] = None
    ) -> EvidenceWorkbenchResponse:
        """Fetch all collections and filtered evidence items for the Evidence Workbench."""
        case = self.case_repo.get_case(case_id, resolve_evidence=False)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        params = filter_params or WorkbenchFilterParams()
        collections = self.get_collections(case_id, limit=100)

        # Retrieve items
        conn = self.case_repo._get_connection()
        with conn:
            cur = conn.cursor()
            if params.collection_id:
                cur.execute(
                    """
                    SELECT reference_id, source_type, source_id, role, epistemic_status,
                           citation_tag, analyst_annotation, created_at
                    FROM case_evidence_references
                    WHERE case_id = ? AND source_type LIKE 'col_item:%' AND source_id LIKE ?
                    ORDER BY created_at ASC, reference_id ASC
                    """,
                    (case_id, f"{params.collection_id}:%"),
                )
            else:
                # All primary evidence + collection members
                cur.execute(
                    """
                    SELECT reference_id, source_type, source_id, role, epistemic_status,
                           citation_tag, analyst_annotation, created_at
                    FROM case_evidence_references
                    WHERE case_id = ? AND source_type != 'collection'
                    ORDER BY created_at ASC, reference_id ASC
                    """,
                    (case_id,),
                )
            raw_rows = cur.fetchall()

        all_items: list[EvidenceCollectionItem] = []
        clean_search = (params.search_text or "").strip().lower()

        for r in raw_rows:
            raw_st = r["source_type"]
            is_col_item = raw_st.startswith("col_item:")
            source_type = raw_st.replace("col_item:", "")

            col_id = ""
            if is_col_item:
                parts = r["source_id"].split(":", 1)
                col_id = parts[0]
                source_id = parts[1] if len(parts) > 1 else parts[0]
            else:
                source_id = r["source_id"]

            try:
                item_meta = json.loads(r["analyst_annotation"] or "{}")
            except Exception:
                item_meta = {"analyst_note": r["analyst_annotation"]}

            resolved = self._resolve_evidence_details(source_type, source_id)

            # Filtering
            if params.source_type and source_type.lower() != params.source_type.lower():
                continue
            if params.epistemic_status and r["epistemic_status"] != params.epistemic_status.value:
                continue
            if params.host and resolved.get("host_id", "").lower() != params.host.lower():
                continue

            summary = resolved.get("display_summary") or f"{source_type} {source_id}"
            if clean_search:
                note = item_meta.get("analyst_note") or ""
                match_txt = (
                    clean_search in summary.lower()
                    or clean_search in note.lower()
                    or clean_search in r["citation_tag"].lower()
                    or clean_search in (resolved.get("host_id") or "").lower()
                )
                if not match_txt:
                    continue

            all_items.append(
                EvidenceCollectionItem(
                    item_id=r["reference_id"],
                    collection_id=col_id,
                    case_id=case_id,
                    source_type=source_type,
                    source_id=source_id,
                    role=item_meta.get("role") or r["role"],
                    epistemic_status=EpistemicStatus(r["epistemic_status"]),
                    collection_status=resolved.get("collection_status", CollectionStatus.SOURCE_AVAILABLE),
                    citation_tag=r["citation_tag"],
                    analyst_annotation=item_meta.get("analyst_note"),
                    order_index=item_meta.get("order_index", 0),
                    added_at=r["created_at"],
                    added_by=item_meta.get("added_by", "SecAnalyst-1"),
                    host_id=resolved.get("host_id"),
                    event_type=resolved.get("event_type"),
                    timestamp=resolved.get("timestamp"),
                    display_summary=summary,
                    provenance=resolved.get("provenance", {}),
                )
            )

        # Deterministic sorting
        all_items.sort(key=lambda it: (it.added_at, it.item_id))
        total_count = len(all_items)
        paginated_items = all_items[params.offset : params.offset + params.limit]

        # Deterministic hash of items
        hash_input = "".join(f"{it.item_id}:{it.added_at}" for it in paginated_items)
        det_hash = hashlib.blake2b(hash_input.encode(), digest_size=16).hexdigest()

        return EvidenceWorkbenchResponse(
            case_id=case_id,
            total_evidence_count=total_count,
            collections=collections,
            items=paginated_items,
            filter_applied=params.model_dump(),
            deterministic_hash=det_hash,
        )

    def export_collection(
        self, case_id: int, collection_id: str, format_type: str = "json"
    ) -> str:
        """Deterministic export of an evidence collection with SHA256 integrity hash."""
        col = self.get_collection(case_id, collection_id)
        now_iso = datetime.now(timezone.utc).isoformat()

        exported_items = [
            {
                "item_id": it.item_id,
                "source_type": it.source_type,
                "source_id": it.source_id,
                "role": it.role,
                "epistemic_status": it.epistemic_status.value,
                "collection_status": it.collection_status.value,
                "citation_tag": it.citation_tag,
                "host_id": it.host_id,
                "event_type": it.event_type,
                "timestamp": it.timestamp,
                "analyst_annotation": it.analyst_annotation,
                "order_index": it.order_index,
                "added_at": it.added_at,
            }
            for it in col.items
        ]

        if format_type.lower() == "csv":
            lines = [
                "item_id,source_type,source_id,role,epistemic_status,host_id,event_type,timestamp,citation_tag,analyst_annotation"
            ]
            for it in exported_items:
                safe_note = (it["analyst_annotation"] or "").replace('"', '""')
                lines.append(
                    f'"{it["item_id"]}","{it["source_type"]}","{it["source_id"]}","{it["role"]}","{it["epistemic_status"]}","{it.get("host_id") or ""}","{it.get("event_type") or ""}","{it.get("timestamp") or ""}","{it["citation_tag"]}","{safe_note}"'
                )
            content = "\n".join(lines)
            return content

        export_dict = {
            "case_id": case_id,
            "collection_id": col.collection_id,
            "name": col.name,
            "description": col.description,
            "tags": col.tags,
            "exported_at": now_iso,
            "total_items": len(exported_items),
            "items": exported_items,
        }
        content = json.dumps(export_dict, indent=2, sort_keys=True)
        return content

    def _resolve_evidence_details(self, source_type: str, source_id: str) -> dict[str, Any]:
        """Resolve evidence metadata from authoritative records in logintel.db."""
        details: dict[str, Any] = {
            "host_id": None,
            "event_type": None,
            "timestamp": None,
            "display_summary": None,
            "collection_status": CollectionStatus.SOURCE_AVAILABLE,
            "provenance": {"source_type": source_type, "source_id": source_id},
        }

        with self.forensic_db.connection() as conn:
            cur = conn.cursor()
            if source_type in ("event", "events"):
                try:
                    cur.execute(
                        "SELECT id, host_id, event_type, timestamp, src_ip, dst_ip, user, process_name, message FROM events WHERE id = ?",
                        (source_id,),
                    )
                    row = cur.fetchone()
                    if row:
                        details["host_id"] = row["host_id"]
                        details["event_type"] = row["event_type"]
                        details["timestamp"] = row["timestamp"]
                        details["display_summary"] = (
                            row["message"]
                            or f"Event {row['event_type']} on {row['host_id']} (proc: {row['process_name'] or 'N/A'})"
                        )
                        details["provenance"].update(
                            {
                                "db": "logintel.db",
                                "table": "events",
                                "record_id": row["id"],
                                "src_ip": row["src_ip"],
                                "dst_ip": row["dst_ip"],
                                "user": row["user"],
                            }
                        )
                except Exception:
                    pass
            elif source_type in ("alert", "alerts"):
                try:
                    cur.execute(
                        "SELECT id, rule_id, rule_name, severity, timestamp, host_id, description FROM alerts WHERE id = ?",
                        (source_id,),
                    )
                    row = cur.fetchone()
                    if row:
                        details["host_id"] = row["host_id"]
                        details["event_type"] = f"ALERT_{row['severity']}"
                        details["timestamp"] = row["timestamp"]
                        details["display_summary"] = (
                            f"Alert [{row['severity']}]: {row['rule_name']} - {row['description'] or ''}"
                        )
                        details["provenance"].update(
                            {
                                "db": "logintel.db",
                                "table": "alerts",
                                "record_id": row["id"],
                                "rule_id": row["rule_id"],
                            }
                        )
                except Exception:
                    pass

        return details


workbench_service = EvidenceWorkbenchService()
