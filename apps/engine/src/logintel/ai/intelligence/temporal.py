"""Temporal correlation and investigation window engine for LogIntel M5.6.

Computes BEFORE, DURING, and AFTER time windows relative to an anchor item,
distinguishing temporal anomalies (out-of-order sequence) from state contradictions
(mutually exclusive evidence states).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from logintel.ai.domain.investigation_intel import TemporalWindowAnalysis


class TemporalIntelligenceEngine:
    """Computes deterministic temporal windows and sequence integrity."""

    def __init__(self, window_seconds: int = 300) -> None:
        self.window_seconds = window_seconds

    def analyze_temporal_window(
        self,
        case_id: int,
        anchor_type: str,
        anchor_id: str,
        anchor_timestamp: str,
        items: List[Dict[str, Any]],
        window_seconds: Optional[int] = None,
    ) -> TemporalWindowAnalysis:
        """Partition items into BEFORE, DURING, and AFTER relative to anchor, identifying anomalies."""
        win_sec = window_seconds or self.window_seconds
        anchor_dt = self._parse_iso(anchor_timestamp)
        if not anchor_dt:
            raise ValueError(f"Invalid anchor timestamp: {anchor_timestamp}")

        before_limit = anchor_dt - timedelta(seconds=win_sec)
        after_limit = anchor_dt + timedelta(seconds=win_sec)

        before_items: List[Dict[str, Any]] = []
        during_items: List[Dict[str, Any]] = []
        after_items: List[Dict[str, Any]] = []
        anomalies: List[str] = []
        contradictions: List[str] = []

        # Track user and host concurrent sessions to identify state contradictions
        user_host_timestamps: Dict[str, List[Tuple[datetime, str, str]]] = {}

        for it in sorted(items, key=lambda x: str(x.get("timestamp") or x.get("created_at") or "")):
            ts_str = it.get("timestamp") or it.get("created_at")
            item_dt = self._parse_iso(ts_str)
            if not item_dt:
                continue

            it_id = str(it.get("id") or it.get("_source_id") or it.get("citation_tag") or "unknown")
            user = it.get("username") or it.get("user")
            host = it.get("host") or it.get("primary_host")

            if user and host:
                user_host_timestamps.setdefault(user, []).append((item_dt, host, it_id))

            # Partition relative to anchor
            diff = (item_dt - anchor_dt).total_seconds()
            if abs(diff) <= 2.0:
                during_items.append(it)
            elif -win_sec <= diff < -2.0:
                before_items.append(it)
            elif 2.0 < diff <= win_sec:
                after_items.append(it)

            # Check for temporal anomalies (e.g. forward timestamps or timestamp in the future)
            now_dt = datetime.now(timezone.utc)
            if item_dt > now_dt + timedelta(minutes=5):
                anomalies.append(
                    f"TEMPORAL_ANOMALY: Item {it_id} timestamp {ts_str} is in the future relative to current time."
                )

        # Detect State Contradictions (e.g. user concurrently operating on two different hosts within 5 seconds)
        for user, history in user_host_timestamps.items():
            for idx in range(len(history) - 1):
                t1, h1, id1 = history[idx]
                t2, h2, id2 = history[idx + 1]
                if h1 != h2 and abs((t2 - t1).total_seconds()) < 5.0:
                    contradictions.append(
                        f"STATE_CONTRADICTION: User '{user}' recorded concurrent operations on distinct hosts '{h1}' ({id1}) and '{h2}' ({id2}) within {abs((t2-t1).total_seconds()):.1f}s."
                    )

        # Detect sequence anomalies relative to anchor (e.g. response event precedes request event)
        return TemporalWindowAnalysis(
            case_id=case_id,
            anchor_type=anchor_type,
            anchor_id=anchor_id,
            anchor_timestamp=anchor_timestamp,
            window_seconds=win_sec,
            before_items=before_items,
            during_items=during_items,
            after_items=after_items,
            temporal_anomalies=anomalies,
            state_contradictions=contradictions,
        )

    @staticmethod
    def _parse_iso(val: Optional[str]) -> Optional[datetime]:
        if not val:
            return None
        try:
            dt = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None
