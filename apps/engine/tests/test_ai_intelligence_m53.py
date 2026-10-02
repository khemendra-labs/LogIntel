"""LogIntel Milestone 5.3 Investigation Intelligence and Evidence Retrieval Tests.

Validates deterministic evidence retrieval, bundle synthesis, entity pivots across all 7 types,
timeline reconstruction, conflict detection, gap auditing, intent classification, and API endpoints.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from logintel.ai.config import AIConfig, AIProviderType
from logintel.ai.domain.bundle import (
    EvidenceConflict,
    EvidenceCoverage,
    EvidenceGap,
    EvidenceItem,
    EvidenceRole,
    InvestigationEvidenceBundle,
)
from logintel.ai.domain.evidence import EvidenceType
from logintel.ai.domain.intelligence import (
    Hypothesis,
    HypothesisConfidence,
    InvestigationIntent,
    QueryProposal,
)
from logintel.ai.domain.response import AIInvestigationResponse, Claim, CitationRef
from logintel.ai.evidence.retriever import EvidenceRetriever
from logintel.ai.intelligence.classifier import QuestionClassifier
from logintel.ai.provider.mock import MockAIProvider
from logintel.ai.service import AIService
from logintel.api.app import app
from logintel.api.auth import get_current_token
from logintel.storage.db import Database
from logintel.storage.investigation_repo import InvestigationRepository


@pytest.fixture
def mock_db():
    """Create a pristine temporary database seeded with comprehensive forensic evidence."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "test_m53.db"
        database = Database(db_path)
        database.initialize()
        with database.connection() as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO hosts (id, hostname, first_seen, last_seen) VALUES ('h1', 'srv-prod-01', '2026-09-30T00:00:00Z', '2026-09-30T23:59:59Z')")
            cur.execute("INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml) VALUES ('rule.ssh', 'SSH Failure', 'SSH brute force', 'MEDIUM', 'Auth', 'pattern', 'yaml')")
            cur.execute("INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml) VALUES ('rule.priv', 'Sudo Execution', 'Privilege Escalation', 'HIGH', 'Priv', 'pattern', 'yaml')")

            # Seed events
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint)
                VALUES ('ev-01', '2026-09-30T10:00:00Z', '2026-09-30T10:00:01Z', 'srv-prod-01', 'auth.log', 'syslog', 'NOTICE', 'login', 'failure', 'Failed password for admin', 'Failed password for admin from 192.168.1.100 port 22', 'openssh', 'fp-1')
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint)
                VALUES ('ev-02', '2026-09-30T10:05:00Z', '2026-09-30T10:05:01Z', 'srv-prod-01', 'auth.log', 'syslog', 'NOTICE', 'login', 'failure', 'Failed password for admin', 'Failed password for admin from 192.168.1.100 port 22', 'openssh', 'fp-2')
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint)
                VALUES ('ev-03', '2026-09-30T10:10:00Z', '2026-09-30T10:10:01Z', 'srv-prod-01', 'auth.log', 'syslog', 'WARNING', 'login', 'success', 'Accepted password for admin', 'Accepted password for admin from 192.168.1.100 port 22', 'openssh', 'fp-3')
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint)
                VALUES ('ev-04', '2026-09-30T10:15:00Z', '2026-09-30T10:15:01Z', 'srv-prod-01', 'auth.log', 'syslog', 'CRITICAL', 'exec', 'success', 'admin executed /usr/bin/id as root', 'COMMAND=/usr/bin/id', 'auditd', 'fp-4')
                """
            )

            # Seed alert 1
            cur.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
                VALUES (1, 'rule.ssh', 'dedup-1', 'SSH Brute Force Attack', 'SSH Desc', 'WARNING', 'OPEN', 'srv-prod-01', '2026-09-30T10:00:00Z', '2026-09-30T10:05:00Z', 2)
                """
            )

            # Seed detections and detection evidence
            cur.execute(
                """
                INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count)
                VALUES (1, 1, 'rule.ssh', '2026-09-30T10:05:00Z', 'srv-prod-01', 'SSH Brute Force Detected', 2)
                """
            )
            cur.execute("INSERT INTO detection_evidence (detection_id, event_id, role) VALUES (1, 'ev-01', 'primary')")
            cur.execute("INSERT INTO detection_evidence (detection_id, event_id, role) VALUES (1, 'ev-02', 'supporting')")

            # Seed incident
            cur.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
                VALUES (101, 'INC-2026-001', 'Suspicious Host Compromise', 'Summary', 'CRITICAL', 'OPEN', 'srv-prod-01', 'admin', '2026-09-30T10:00:00Z', '2026-09-30T10:15:00Z', 1, 4)
                """
            )
            cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (101, 1)")

            # Seed incident entities (all 7 types)
            cur.execute("INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name, metadata_json) VALUES (101, 'host:srv-prod-01', 'HOST', 'srv-prod-01', '{}')")
            cur.execute("INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name, metadata_json) VALUES (101, 'user:admin', 'USER', 'admin', '{}')")
            cur.execute("INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name, metadata_json) VALUES (101, 'ip:192.168.1.100', 'IP', '192.168.1.100', '{}')")
            cur.execute("INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name, metadata_json) VALUES (101, 'process:sshd', 'PROCESS', 'sshd', '{}')")
            cur.execute("INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name, metadata_json) VALUES (101, 'command:sudo /usr/bin/id', 'COMMAND', 'sudo /usr/bin/id', '{}')")
            cur.execute("INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name, metadata_json) VALUES (101, 'file:/var/log/auth.log', 'FILE', '/var/log/auth.log', '{}')")
            cur.execute("INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name, metadata_json) VALUES (101, 'session:sess-99', 'SESSION', 'Session #99', '{}')")

            # Seed relationships
            cur.execute(
                """
                INSERT INTO incident_relationships (id, incident_id, source_entity_key, target_entity_key, relationship_type, confidence, evidence_event_ids_json)
                VALUES (1, 101, 'ip:192.168.1.100', 'user:admin', 'AUTHENTICATED_TO', 'STRONG', '["ev-01"]')
                """
            )
            conn.commit()

        yield database


# =========================================================================
# 1. Question Classifier Tests
# =========================================================================

def test_question_classifier_intents():
    """Verify deterministic intent classification across all 10 M5.3 intents."""
    classifier = QuestionClassifier()

    cases = [
        ("What happened in this incident?", InvestigationIntent.SUMMARY),
        ("Show me the timeline of events.", InvestigationIntent.TIMELINE),
        ("What activity was observed for host srv-prod-01?", InvestigationIntent.ENTITY_ANALYSIS),
        ("Why was alert ALT-SSH-001 created?", InvestigationIntent.ALERT_EXPLANATION),
        ("Explain detection DET-SSH-01", InvestigationIntent.DETECTION_EXPLANATION),
        ("How did the attacker progress through the attack path?", InvestigationIntent.ATTACK_PATH_EXPLANATION),
        ("Explain the MITRE ATT&CK techniques associated with this", InvestigationIntent.MITRE_EXPLANATION),
        ("Could this be credential stuffing or lateral movement?", InvestigationIntent.HYPOTHESIS),
        ("What telemetry or evidence is missing?", InvestigationIntent.EVIDENCE_GAP),
        ("What queries should I run next for threat hunting?", InvestigationIntent.NEXT_QUERY),
    ]

    for q, expected_intent in cases:
        intent, _ = classifier.classify(q)
        assert intent == expected_intent, f"Failed for '{q}': expected {expected_intent}, got {intent}"


def test_question_classifier_entity_extraction():
    """Verify entity key extraction from natural language question."""
    classifier = QuestionClassifier()

    intent, entity = classifier.classify("What did 192.168.1.100 do on this host?")
    assert entity == "ip:192.168.1.100"

    intent, entity = classifier.classify("Tell me about user admin actions")
    assert entity == "user:admin"


# =========================================================================
# 2. Evidence Retriever Tests
# =========================================================================

def test_evidence_retriever_bundle_deterministic(mock_db):
    """Verify evidence retrieval produces deterministic, stable results."""
    retriever = EvidenceRetriever(database=mock_db)

    bundle1 = retriever.retrieve_bundle(incident_id=101)
    bundle2 = retriever.retrieve_bundle(incident_id=101)

    assert len(bundle1.items) == len(bundle2.items)
    for i1, i2 in zip(bundle1.items, bundle2.items):
        assert i1.evidence_id == i2.evidence_id
        assert i1.evidence_type == i2.evidence_type
        assert i1.relevance_score == i2.relevance_score
        assert i1.citation_tag == i2.citation_tag


def test_evidence_retriever_all_seven_entity_types(mock_db):
    """Verify retriever supports all 7 entity types and extracts them properly."""
    retriever = EvidenceRetriever(database=mock_db)
    bundle = retriever.retrieve_bundle(incident_id=101)

    entity_items = [i for i in bundle.items if i.evidence_type == EvidenceType.ENTITY]
    entity_keys = {i.evidence_id for i in entity_items}

    expected_types = {"host:srv-prod-01", "user:admin", "ip:192.168.1.100", "process:sshd", "command:sudo /usr/bin/id", "file:/var/log/auth.log", "session:sess-99"}
    assert expected_types.issubset(entity_keys)

    # Test entity-centric retrieval
    ip_bundle = retriever.retrieve_entity_evidence(101, "IP", "192.168.1.100")
    assert any("192.168.1.100" in i.evidence_id for i in ip_bundle.items)


def test_evidence_retriever_timeline_ordering(mock_db):
    """Verify timeline evidence is strictly chronologically ordered."""
    retriever = EvidenceRetriever(database=mock_db)
    timeline = retriever.retrieve_timeline_evidence(incident_id=101)

    assert len(timeline) >= 2
    timestamps = [i.timestamp for i in timeline]
    assert timestamps == sorted(timestamps)


def test_evidence_retriever_surrounding_events(mock_db):
    """Verify surrounding events retrieval groups before, target, and after correctly."""
    retriever = EvidenceRetriever(database=mock_db)
    surrounding = retriever.retrieve_surrounding_events(incident_id=101, event_id="ev-02", window_seconds=1800)

    assert len(surrounding["target"]) == 1
    assert surrounding["target"][0].evidence_id == "ev-02"
    assert surrounding["target"][0].role == EvidenceRole.PRIMARY

    assert any(i.evidence_id == "ev-01" for i in surrounding["before"])
    assert any(i.evidence_id == "ev-03" for i in surrounding["after"])


def test_evidence_retriever_conflict_and_gap_detection(mock_db):
    """Verify conflict detection and visibility gap auditing."""
    retriever = EvidenceRetriever(database=mock_db)
    bundle = retriever.retrieve_bundle(incident_id=101)

    # Check gaps (auditd should be reported missing since only syslog auth.log is seeded)
    assert len(bundle.gaps) > 0
    assert any("audit" in g.category.lower() for g in bundle.gaps)

    # Check coverage calculation
    assert bundle.coverage.selected_count == len(bundle.items)
    assert EvidenceType.EVENT.value in bundle.coverage.available_evidence_types


# =========================================================================
# 3. AIService Investigation Question & Query Proposal Tests
# =========================================================================

@pytest.mark.asyncio
async def test_ai_service_ask_question_pipeline(mock_db):
    """Verify end-to-end question pipeline execution with mock provider."""
    mock_payload = {
        "answer_markdown": "Based on observed authentication telemetry, admin failed SSH authentication twice before succeeding.",
        "epistemic_status": "OBSERVED",
        "claims": [
            {
                "claim_text": "Failed password for admin observed at 10:00:00Z.",
                "status": "OBSERVED",
                "evidence_refs": [{"evidence_type": "event", "evidence_id": "ev-01", "citation_tag": "[event:ev-01]"}],
            }
        ],
        "citations": [{"evidence_type": "event", "evidence_id": "ev-01", "citation_tag": "[event:ev-01]"}],
        "hypotheses": [
            {
                "statement": "The IP 192.168.1.100 may have conducted password spraying or brute force.",
                "confidence": "MEDIUM",
                "supporting_evidence": [{"evidence_type": "event", "evidence_id": "ev-01", "citation_tag": "[event:ev-01]"}],
                "contradicting_evidence": [],
                "rationale": "Consecutive rapid failed attempts from identical external IP.",
                "unknowns": ["Source port randomization frequency"]
            }
        ],
        "suggested_query_proposals": [
            {
                "proposal_id": "qp-101",
                "intent": "Search for other login failures from same IP",
                "target_entity": "192.168.1.100",
                "event_types": ["syslog"],
                "source": "auth.log",
                "filters": {"action": "login", "outcome": "failure"},
                "limit": 10,
                "rationale": "Find potential broader spraying targets",
                "is_executed": False
            }
        ],
    }

    mock_provider = MockAIProvider(default_response=json.dumps(mock_payload))
    service = AIService(
        config=AIConfig(provider={"provider_type": AIProviderType.MOCK}),
        provider=mock_provider,
        database=mock_db,
    )

    resp = await service.ask_question(incident_id=101, question="What happened during authentication?")

    assert resp.epistemic_status == "OBSERVED"
    assert resp.intent == InvestigationIntent.SUMMARY
    assert len(resp.claims) == 1
    assert resp.claims[0].status == "OBSERVED"
    assert len(resp.hypotheses) == 1
    assert resp.hypotheses[0].confidence == HypothesisConfidence.MEDIUM
    assert resp.hypotheses[0].is_hypothesis is True
    assert len(resp.suggested_query_proposals) == 1
    assert resp.suggested_query_proposals[0].is_executed is False

    # Test Query Proposal Preview
    preview = service.preview_query_proposal(101, resp.suggested_query_proposals[0])
    assert preview["is_preview_only"] is True
    assert preview["executed"] is False
    assert preview["matched_count"] >= 1
    assert any(e["id"] == "ev-01" for e in preview["events"])


# =========================================================================
# 4. API Endpoints Verification
# =========================================================================

def test_api_m53_endpoints(mock_db, monkeypatch):
    """Verify M5.3 API endpoints: question, evidence, coverage, query preview."""
    import logintel.api.routes as routes
    from logintel.storage.incidents_repo import IncidentsRepository
    from logintel.storage.investigation_repo import InvestigationRepository

    # Wire test database
    inc_repo = IncidentsRepository(mock_db)
    inv_repo = InvestigationRepository(mock_db, incidents_repository=inc_repo)
    mock_provider = MockAIProvider(
        default_response=json.dumps({
            "answer_markdown": "API test response summary",
            "epistemic_status": "OBSERVED",
            "claims": [
                {
                    "claim_text": "Observed SSH login failure",
                    "status": "OBSERVED",
                    "evidence_refs": [{"evidence_type": "event", "evidence_id": "ev-01", "citation_tag": "[event:ev-01]"}],
                }
            ],
            "citations": [{"evidence_type": "event", "evidence_id": "ev-01", "citation_tag": "[event:ev-01]"}],
        })
    )
    test_ai_service = AIService(
        config=AIConfig(provider={"provider_type": AIProviderType.MOCK}),
        provider=mock_provider,
        database=mock_db,
    )
    test_ai_service.assembler.inv_repo = inv_repo
    test_ai_service.retriever.inv_repo = inv_repo

    import sys
    inc_mod = sys.modules["logintel.storage.incidents_repo"]
    inv_mod = sys.modules["logintel.storage.investigation_repo"]
    ai_mod = sys.modules["logintel.ai.service"]

    monkeypatch.setattr(ai_mod, "ai_service", test_ai_service)
    monkeypatch.setattr(inc_mod, "incidents_repo", inc_repo)
    monkeypatch.setattr(inv_mod, "investigation_repo", inv_repo)

    client = TestClient(app)
    token = get_current_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. POST /question
    q_res = client.post(
        "/api/v1/ai/investigations/101/question",
        json={"question": "What is the login sequence?"},
        headers=headers,
    )
    assert q_res.status_code == 200
    q_data = q_res.json()
    assert "answer_markdown" in q_data
    assert q_data["intent"] == "TIMELINE"

    # 2. GET /evidence
    ev_res = client.get("/api/v1/ai/investigations/101/evidence", headers=headers)
    assert ev_res.status_code == 200
    ev_data = ev_res.json()
    assert "items" in ev_data
    assert len(ev_data["items"]) > 0

    # 3. GET /coverage
    cov_res = client.get("/api/v1/ai/investigations/101/coverage", headers=headers)
    assert cov_res.status_code == 200
    cov_data = cov_res.json()
    assert "available_evidence_types" in cov_data
    assert cov_data["selected_count"] > 0

    # 4. POST /query/preview
    prev_res = client.post(
        "/api/v1/ai/investigations/101/query/preview",
        json={
            "proposal_id": "prop-1",
            "intent": "Find failed logins",
            "target_entity": "192.168.1.100",
            "event_types": ["syslog"],
            "source": "auth.log",
            "filters": {"outcome": "failure"},
            "limit": 5,
            "is_executed": False
        },
        headers=headers,
    )
    assert prev_res.status_code == 200
    prev_data = prev_res.json()
    assert prev_data["is_preview_only"] is True
    assert prev_data["matched_count"] >= 1
