import hashlib
import json
import pytest

from logintel.collections.models import EpistemicStatus
from logintel.collections.service import workbench_service
from logintel.storage.case_repo import case_repo


@pytest.fixture
def det_case():
    case = case_repo.get_case(1, resolve_evidence=False)
    if not case:
        case = case_repo.create_case(
            incident_id=1,
            title="Determinism Test Case",
            description="Testing determinism across N=10 operations",
            created_by="SecAnalyst-1",
        )
    return case.case_id


def test_n10_identical_collection_listings(det_case):
    """Verify N=10 collection listings yield identical serialized output."""
    col = workbench_service.create_collection(
        case_id=det_case,
        name="Deterministic Col A",
        tags=["det-1", "det-2"],
    )

    outputs = []
    for _ in range(10):
        cols = workbench_service.get_collections(det_case)
        serialized = json.dumps([c.model_dump(mode="json") for c in cols], sort_keys=True)
        outputs.append(serialized)

    assert len(set(outputs)) == 1, "Collection listings across N=10 runs must be bitwise identical!"
    workbench_service.delete_collection(det_case, col.collection_id)


def test_n10_identical_collection_items_ordering(det_case):
    """Verify N=10 collection member queries preserve identical ordering and properties."""
    col = workbench_service.create_collection(
        case_id=det_case,
        name="Deterministic Col Items",
    )
    for i in range(1, 6):
        workbench_service.add_item_to_collection(
            case_id=det_case,
            collection_id=col.collection_id,
            source_type="event",
            source_id=f"det-{i}",
            role="SUPPORTING",
            epistemic_status=EpistemicStatus.OBSERVED,
        )

    digests = []
    for _ in range(10):
        fetched = workbench_service.get_collection(det_case, col.collection_id)
        serialized = json.dumps([it.model_dump(mode="json") for it in fetched.items], sort_keys=True)
        digests.append(hashlib.sha256(serialized.encode()).hexdigest())

    assert len(set(digests)) == 1, "Item ordering across N=10 runs must produce identical SHA256 digest!"
    workbench_service.delete_collection(det_case, col.collection_id)


def test_n10_identical_collection_exports(det_case):
    """Verify N=10 export operations of the same collection produce identical output."""
    col = workbench_service.create_collection(
        case_id=det_case,
        name="Deterministic Col Export",
    )
    workbench_service.add_item_to_collection(
        case_id=det_case,
        collection_id=col.collection_id,
        source_type="event",
        source_id="det-exp-1",
        role="PRIMARY",
        epistemic_status=EpistemicStatus.OBSERVED,
    )

    # Normalize out dynamic export timestamps for content hash testing
    hashes = []
    for _ in range(10):
        csv_out = workbench_service.export_collection(det_case, col.collection_id, format_type="csv")
        hashes.append(hashlib.sha256(csv_out.encode()).hexdigest())

    assert len(set(hashes)) == 1, "CSV exports across N=10 runs must be completely identical!"
    workbench_service.delete_collection(det_case, col.collection_id)
