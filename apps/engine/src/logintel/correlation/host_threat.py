"""Deterministic Host Threat Correlation and MITRE ATT&CK Kill-Chain Engine."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from logintel.correlation.host_graph import HostGraphBuilder
from logintel.correlation.host_threat_models import (
    HostAttackSequence,
    HostThreatAssessment,
    HostThreatStage,
    MitreTactic,
    MitreTechnique,
)
from logintel.logging import get_logger
from logintel.models.events import Severity

logger = get_logger("correlation.host_threat")

# Canonical MITRE ATT&CK Techniques Catalog
TECHNIQUES_CATALOG: Dict[str, MitreTechnique] = {
    "T1078": MitreTechnique(
        id="T1078",
        name="Valid Accounts",
        tactic=MitreTactic.INITIAL_ACCESS,
        description="Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.",
        reference_url="https://attack.mitre.org/techniques/T1078/",
    ),
    "T1110": MitreTechnique(
        id="T1110",
        name="Brute Force",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        description="Adversaries may use brute force techniques to attempt authentication.",
        reference_url="https://attack.mitre.org/techniques/T1110/",
    ),
    "T1059.004": MitreTechnique(
        id="T1059.004",
        name="Unix Shell",
        tactic=MitreTactic.EXECUTION,
        description="Adversaries may abuse Unix shells (sh, bash) for execution.",
        reference_url="https://attack.mitre.org/techniques/T1059/004/",
    ),
    "T1055": MitreTechnique(
        id="T1055",
        name="Process Injection",
        tactic=MitreTactic.DEFENSE_EVASION,
        description="Adversaries may inject code into processes in order to evade process-based defenses.",
        reference_url="https://attack.mitre.org/techniques/T1055/",
    ),
    "T1620": MitreTechnique(
        id="T1620",
        name="Reflective Code Loading / Memory Execution",
        tactic=MitreTactic.DEFENSE_EVASION,
        description="Adversaries may reflectively execute code in memory or shared memory filesystems (/dev/shm, memfd:).",
        reference_url="https://attack.mitre.org/techniques/T1620/",
    ),
    "T1548.003": MitreTechnique(
        id="T1548.003",
        name="Sudo and Sudo Caching",
        tactic=MitreTactic.PRIVILEGE_ESCALATION,
        description="Adversaries may execute commands with elevated privileges via sudo.",
        reference_url="https://attack.mitre.org/techniques/T1548/003/",
    ),
    "T1053.003": MitreTechnique(
        id="T1053.003",
        name="Cron",
        tactic=MitreTactic.PERSISTENCE,
        description="Adversaries may abuse the cron utility to perform task scheduling for initial or recurring persistence.",
        reference_url="https://attack.mitre.org/techniques/T1053/003/",
    ),
    "T1543.002": MitreTechnique(
        id="T1543.002",
        name="Systemd Service",
        tactic=MitreTactic.PERSISTENCE,
        description="Adversaries may create or modify systemd services to establish persistence.",
        reference_url="https://attack.mitre.org/techniques/T1543/002/",
    ),
    "T1098.004": MitreTechnique(
        id="T1098.004",
        name="SSH Authorized Keys",
        tactic=MitreTactic.PERSISTENCE,
        description="Adversaries may modify SSH authorized_keys to maintain persistent access to Linux systems.",
        reference_url="https://attack.mitre.org/techniques/T1098/004/",
    ),
    "T1611": MitreTechnique(
        id="T1611",
        name="Escape to Host",
        tactic=MitreTactic.PRIVILEGE_ESCALATION,
        description="Adversaries may break out of a container environment to gain access to the underlying host system.",
        reference_url="https://attack.mitre.org/techniques/T1611/",
    ),
    "T1071": MitreTechnique(
        id="T1071",
        name="Application Layer Protocol",
        tactic=MitreTactic.COMMAND_AND_CONTROL,
        description="Adversaries may communicate using application layer protocols to avoid detection.",
        reference_url="https://attack.mitre.org/techniques/T1071/",
    ),
    "T1571": MitreTechnique(
        id="T1571",
        name="Non-Standard Port",
        tactic=MitreTactic.COMMAND_AND_CONTROL,
        description="Adversaries may communicate using a protocol and port pairing that is typically not used for that protocol.",
        reference_url="https://attack.mitre.org/techniques/T1571/",
    ),
    "T1082": MitreTechnique(
        id="T1082",
        name="System Information Discovery",
        tactic=MitreTactic.DISCOVERY,
        description="An adversary may attempt to get detailed information about the operating system and hardware.",
        reference_url="https://attack.mitre.org/techniques/T1082/",
    ),
    "T1547.006": MitreTechnique(
        id="T1547.006",
        name="Kernel Modules and Extensions",
        tactic=MitreTactic.PERSISTENCE,
        description="Adversaries may modify the kernel by loading kernel modules or drivers to execute malicious code.",
        reference_url="https://attack.mitre.org/techniques/T1547/006/",
    ),
}

# Regex matchers for heuristic stage mapping
RE_SHM_OR_MEM = re.compile(r"^(/dev/shm|/tmp|/var/tmp|/memfd:|memfd:)", re.IGNORECASE)
RE_CRON_PATH = re.compile(r".*(cron|crontab).*", re.IGNORECASE)
RE_SYSTEMD_PATH = re.compile(r".*(systemd|\.service).*", re.IGNORECASE)
RE_SSH_KEYS = re.compile(r".*authorized_keys.*", re.IGNORECASE)
RE_SHELL_NAMES = {"bash", "sh", "zsh", "dash", "python", "python3", "perl", "nc", "netcat", "socat"}
ADVERSARY_PORTS = {4444, 1337, 31337, 6667, 8888, 9999}


class HostThreatCorrelator:
    """Evaluates multi-source host events and alerts into deterministic attack sequences and assessments."""

    def __init__(self, graph_builder: Optional[HostGraphBuilder] = None) -> None:
        self.graph_builder = graph_builder or HostGraphBuilder()

    def correlate_host_telemetry(
        self,
        host: str,
        events: List[Dict[str, Any]],
        alerts: Optional[List[Dict[str, Any]]] = None,
        incident_id: Optional[int] = None,
    ) -> HostThreatAssessment:
        """Analyze host events and alerts, construct attack sequences, and synthesize threat assessment."""
        alerts = alerts or []
        stages: List[HostThreatStage] = []
        observed_sources: Set[str] = set()

        # 1. Process operational alerts into stages
        for alert in alerts:
            stage = self._classify_alert_to_stage(alert)
            if stage:
                stages.append(stage)

        # 2. Process canonical events into stages
        for ev in events:
            source = ev.get("source") or ev.get("parser") or "system"
            observed_sources.add(str(source))
            ev_stages = self._classify_event_to_stages(ev)
            stages.extend(ev_stages)

        # 3. Sort stages deterministically by timestamp, tactic, then stage_id
        stages.sort(key=lambda s: (s.timestamp, s.tactic.value, s.stage_id))

        # 4. Synthesize attack sequences
        attack_sequences = self._synthesize_sequences(host=host, stages=stages)

        # 5. Extract unique MITRE tactics and techniques
        tactics_set: Set[str] = set()
        techniques_map: Dict[str, MitreTechnique] = {}
        for s in stages:
            tactics_set.add(s.tactic.value)
            if s.technique:
                techniques_map[s.technique.id] = s.technique

        tactics_list = sorted(list(tactics_set))
        techniques_list = [techniques_map[k] for k in sorted(techniques_map.keys())]

        # 6. Build host graph to get entity/relationship metrics
        graph = self.graph_builder.build_from_events(host=host, events=events)
        node_count = len(graph.nodes)
        edge_count = len(graph.edges)

        # 7. Evaluate overall threat score and primary scenario
        if attack_sequences:
            primary_seq = max(attack_sequences, key=lambda s: (s.threat_score, len(s.stages)))
            overall_threat_score = primary_seq.threat_score
            overall_severity = primary_seq.escalated_severity
            primary_scenario = primary_seq.scenario_name
            epistemic_confidence = primary_seq.epistemic_confidence
        else:
            overall_threat_score = 0.0
            overall_severity = Severity.NOTICE
            primary_scenario = "Benign Host Activity"
            epistemic_confidence = 1.0

        # 8. Deterministic investigative executive summary
        summary = self._generate_assessment_summary(
            host=host,
            scenario=primary_scenario,
            tactics=tactics_list,
            stage_count=len(stages),
            node_count=node_count,
            severity=overall_severity,
        )

        return HostThreatAssessment(
            host=host,
            incident_id=incident_id,
            assessed_at=datetime.now(timezone.utc),
            overall_threat_score=overall_threat_score,
            overall_severity=overall_severity,
            primary_scenario=primary_scenario,
            epistemic_confidence=epistemic_confidence,
            attack_sequences=attack_sequences,
            mitre_tactics_observed=tactics_list,
            mitre_techniques_observed=techniques_list,
            telemetry_source_diversity=len(observed_sources),
            summary=summary,
            node_count=node_count,
            edge_count=edge_count,
        )

    # =========================================================================
    # Internal Classification & Synthesis
    # =========================================================================

    def _classify_alert_to_stage(self, alert: Dict[str, Any]) -> Optional[HostThreatStage]:
        """Convert an operational alert record into a HostThreatStage."""
        aid = alert.get("id") or 0
        rule_id = alert.get("rule_id", "")
        sev_str = alert.get("severity", "NOTICE")
        try:
            sev = Severity(sev_str)
        except Exception:
            sev = Severity.NOTICE

        ts = self._parse_dt(alert.get("first_seen") or alert.get("timestamp"))

        # Map by rule ID
        tactic = MitreTactic.EXECUTION
        tech: Optional[MitreTechnique] = None

        if rule_id.startswith("auth."):
            tactic = MitreTactic.INITIAL_ACCESS
            tech = TECHNIQUES_CATALOG.get("T1078")
            if "bruteforce" in rule_id or "spray" in rule_id:
                tactic = MitreTactic.CREDENTIAL_ACCESS
                tech = TECHNIQUES_CATALOG.get("T1110")
        elif rule_id.startswith("priv."):
            tactic = MitreTactic.PRIVILEGE_ESCALATION
            tech = TECHNIQUES_CATALOG.get("T1548.003")
        elif rule_id.startswith("proc."):
            tactic = MitreTactic.EXECUTION
            tech = TECHNIQUES_CATALOG.get("T1059.004")
            if "reconnaissance" in rule_id:
                tactic = MitreTactic.DISCOVERY
                tech = TECHNIQUES_CATALOG.get("T1082")
        elif rule_id.startswith("network.") or rule_id.startswith("net."):
            tactic = MitreTactic.DISCOVERY
            tech = TECHNIQUES_CATALOG.get("T1082")
        elif rule_id.startswith("sec.") or rule_id.startswith("security."):
            if "memory" in rule_id:
                tactic = MitreTactic.DEFENSE_EVASION
                tech = TECHNIQUES_CATALOG.get("T1620")
            elif "reverse_shell" in rule_id:
                tactic = MitreTactic.COMMAND_AND_CONTROL
                tech = TECHNIQUES_CATALOG.get("T1071")
            elif "cron" in rule_id:
                tactic = MitreTactic.PERSISTENCE
                tech = TECHNIQUES_CATALOG.get("T1053.003")
            elif "systemd" in rule_id:
                tactic = MitreTactic.PERSISTENCE
                tech = TECHNIQUES_CATALOG.get("T1543.002")
            elif "ssh_authorized_keys" in rule_id:
                tactic = MitreTactic.PERSISTENCE
                tech = TECHNIQUES_CATALOG.get("T1098.004")
            elif "container_escape" in rule_id:
                tactic = MitreTactic.PRIVILEGE_ESCALATION
                tech = TECHNIQUES_CATALOG.get("T1611")
            elif "listening_socket" in rule_id:
                tactic = MitreTactic.COMMAND_AND_CONTROL
                tech = TECHNIQUES_CATALOG.get("T1571")
            elif "kernel_module" in rule_id:
                tactic = MitreTactic.PERSISTENCE
                tech = TECHNIQUES_CATALOG.get("T1547.006")

        return HostThreatStage(
            stage_id=f"alert-stage-{aid}-{rule_id}",
            tactic=tactic,
            technique=tech,
            timestamp=ts,
            summary=f"Operational alert triggered: {alert.get('title', rule_id)}",
            alert_ids=[aid] if aid else [],
            epistemic_certainty="OBSERVED",
            severity=sev,
        )

    def _classify_event_to_stages(self, ev: Dict[str, Any]) -> List[HostThreatStage]:
        """Classify a canonical telemetry event into one or more HostThreatStages."""
        ev_id = str(ev.get("id", ""))
        ev_type = str(ev.get("event_type", ""))
        ts = self._parse_dt(ev.get("timestamp"))
        proc_exe = str(ev.get("process_executable") or "")
        proc_cmd = str(ev.get("process_command_line") or "")
        proc_name = str(ev.get("process_name") or "")
        summary = str(ev.get("summary") or "")
        metadata = ev.get("metadata") or {}
        sev = Severity(ev.get("severity", Severity.NOTICE.value)) if isinstance(ev.get("severity"), str) else Severity.NOTICE

        stages: List[HostThreatStage] = []

        # 1. Container breakout / Escape attempt (T1611)
        if ev_type == "CONTAINER_SECURITY_ESCAPE_ATTEMPT" or "escape" in summary.lower():
            stages.append(
                HostThreatStage(
                    stage_id=f"ev-stage-{ev_id}-container-escape",
                    tactic=MitreTactic.PRIVILEGE_ESCALATION,
                    technique=TECHNIQUES_CATALOG.get("T1611"),
                    timestamp=ts,
                    summary=f"Container escape attempt detected: {summary}",
                    event_ids=[ev_id],
                    epistemic_certainty="OBSERVED",
                    severity=Severity.CRITICAL,
                )
            )

        # 2. In-memory or temporary execution (T1620)
        if (ev_type == "PROCESS_EXECUTION" or ev_type == "SUDO_COMMAND") and (
            RE_SHM_OR_MEM.search(proc_exe) or "/dev/shm" in proc_cmd or "memfd:" in proc_cmd
        ):
            stages.append(
                HostThreatStage(
                    stage_id=f"ev-stage-{ev_id}-mem-exec",
                    tactic=MitreTactic.DEFENSE_EVASION,
                    technique=TECHNIQUES_CATALOG.get("T1620"),
                    timestamp=ts,
                    summary=f"In-memory / temporary process execution: {proc_exe or proc_cmd}",
                    event_ids=[ev_id],
                    entity_keys=[f"process:{proc_name}:{proc_exe}"],
                    epistemic_certainty="OBSERVED",
                    severity=Severity.ALERT,
                )
            )

        # 3. Interactive Shell Outbound Connection / Reverse Shell (T1071 / T1059)
        if ev_type == "NETWORK_SOCKET_CONNECTION" and (
            proc_name.lower() in RE_SHELL_NAMES or "reverse" in summary.lower()
        ):
            stages.append(
                HostThreatStage(
                    stage_id=f"ev-stage-{ev_id}-rev-shell",
                    tactic=MitreTactic.COMMAND_AND_CONTROL,
                    technique=TECHNIQUES_CATALOG.get("T1071"),
                    timestamp=ts,
                    summary=f"Shell process established outbound network socket: {proc_name} -> {ev.get('dst_ip')}:{ev.get('dst_port')}",
                    event_ids=[ev_id],
                    entity_keys=[f"ip:{ev.get('dst_ip')}", f"process:{proc_name}"],
                    epistemic_certainty="OBSERVED",
                    severity=Severity.CRITICAL,
                )
            )

        # 4. Filesystem Persistence: Cron (T1053.003)
        if (ev_type in ("FILE_PERSISTENCE_DROP", "FILE_INTEGRITY_MODIFY")) and (
            RE_CRON_PATH.search(summary) or RE_CRON_PATH.search(str(metadata.get("target_path", "")))
        ):
            stages.append(
                HostThreatStage(
                    stage_id=f"ev-stage-{ev_id}-cron-persist",
                    tactic=MitreTactic.PERSISTENCE,
                    technique=TECHNIQUES_CATALOG.get("T1053.003"),
                    timestamp=ts,
                    summary=f"Scheduled task / cron persistence created or modified: {summary}",
                    event_ids=[ev_id],
                    epistemic_certainty="OBSERVED",
                    severity=Severity.WARNING,
                )
            )

        # 5. Filesystem Persistence: Systemd (T1543.002)
        if (ev_type in ("FILE_PERSISTENCE_DROP", "FILE_INTEGRITY_MODIFY")) and (
            RE_SYSTEMD_PATH.search(summary) or RE_SYSTEMD_PATH.search(str(metadata.get("target_path", "")))
        ):
            stages.append(
                HostThreatStage(
                    stage_id=f"ev-stage-{ev_id}-systemd-persist",
                    tactic=MitreTactic.PERSISTENCE,
                    technique=TECHNIQUES_CATALOG.get("T1543.002"),
                    timestamp=ts,
                    summary=f"Systemd service persistence unit dropped or modified: {summary}",
                    event_ids=[ev_id],
                    epistemic_certainty="OBSERVED",
                    severity=Severity.ALERT,
                )
            )

        # 6. Filesystem Persistence: SSH Authorized Keys (T1098.004)
        if (ev_type in ("FILE_PERSISTENCE_DROP", "FILE_INTEGRITY_MODIFY")) and (
            RE_SSH_KEYS.search(summary) or RE_SSH_KEYS.search(str(metadata.get("target_path", "")))
        ):
            stages.append(
                HostThreatStage(
                    stage_id=f"ev-stage-{ev_id}-ssh-keys-persist",
                    tactic=MitreTactic.PERSISTENCE,
                    technique=TECHNIQUES_CATALOG.get("T1098.004"),
                    timestamp=ts,
                    summary=f"SSH authorized_keys modified or backdoor established: {summary}",
                    event_ids=[ev_id],
                    epistemic_certainty="OBSERVED",
                    severity=Severity.ALERT,
                )
            )

        # 7. Sudo Root Privilege Escalation (T1548.003)
        if ev_type == "SUDO_COMMAND" and (
            "bash" in proc_cmd or "sh" in proc_cmd or "su" in proc_cmd or "root" in proc_cmd
        ):
            stages.append(
                HostThreatStage(
                    stage_id=f"ev-stage-{ev_id}-sudo-priv",
                    tactic=MitreTactic.PRIVILEGE_ESCALATION,
                    technique=TECHNIQUES_CATALOG.get("T1548.003"),
                    timestamp=ts,
                    summary=f"Privileged root execution via sudo: {proc_cmd}",
                    event_ids=[ev_id],
                    entity_keys=[f"user:{ev.get('username', 'root')}", f"process:{proc_name}"],
                    epistemic_certainty="OBSERVED",
                    severity=Severity.ALERT,
                )
            )

        # 8. Suspicious Inbound Listening Socket (T1571)
        dst_p = ev.get("dst_port")
        if ev_type == "NETWORK_SOCKET_LISTEN" and dst_p in ADVERSARY_PORTS:
            stages.append(
                HostThreatStage(
                    stage_id=f"ev-stage-{ev_id}-listener",
                    tactic=MitreTactic.COMMAND_AND_CONTROL,
                    technique=TECHNIQUES_CATALOG.get("T1571"),
                    timestamp=ts,
                    summary=f"Inbound listening socket opened on suspicious port {dst_p}",
                    event_ids=[ev_id],
                    entity_keys=[f"socket:tcp:{dst_p}"],
                    epistemic_certainty="OBSERVED",
                    severity=Severity.WARNING,
                )
            )

        # 9. Kernel Module Tampering (T1547.006)
        if ev_type in ("KERNEL_MODULE_LOAD", "KERNEL_SECURITY_ANOMALY"):
            stages.append(
                HostThreatStage(
                    stage_id=f"ev-stage-{ev_id}-kernel-mod",
                    tactic=MitreTactic.PERSISTENCE,
                    technique=TECHNIQUES_CATALOG.get("T1547.006"),
                    timestamp=ts,
                    summary=f"Kernel security anomaly or module load: {summary}",
                    event_ids=[ev_id],
                    epistemic_certainty="OBSERVED",
                    severity=Severity.ALERT,
                )
            )

        return stages

    def _synthesize_sequences(
        self,
        host: str,
        stages: List[HostThreatStage],
    ) -> List[HostAttackSequence]:
        """Group stages into attack sequences, classify scenarios, and calculate threat scores."""
        if not stages:
            return []

        # Collect unique participating entities
        users: Set[str] = set()
        processes: Set[str] = set()
        ips: Set[str] = set()
        for s in stages:
            for k in s.entity_keys:
                if k.startswith("user:"):
                    users.add(k[len("user:"):])
                elif k.startswith("process:"):
                    processes.add(k[len("process:"):].split(":")[0])
                elif k.startswith("ip:"):
                    ips.add(k[len("ip:"):])

        tactics_observed = {s.tactic for s in stages}
        max_sev = max((s.severity for s in stages), key=lambda x: self._severity_weight(x))

        # Scenario identification
        scenario_name = "Multi-Stage Host Takeover Campaign"
        if MitreTactic.INITIAL_ACCESS in tactics_observed and MitreTactic.PRIVILEGE_ESCALATION in tactics_observed:
            scenario_name = "Initial Access Followed by Privilege Escalation"
        elif MitreTactic.PRIVILEGE_ESCALATION in tactics_observed and MitreTactic.PERSISTENCE in tactics_observed:
            scenario_name = "Privilege Escalation & Persistence Establishment"
        elif MitreTactic.DEFENSE_EVASION in tactics_observed and MitreTactic.COMMAND_AND_CONTROL in tactics_observed:
            scenario_name = "In-Memory Execution & Reverse Shell C2"
        elif any("escape" in s.stage_id for s in stages):
            scenario_name = "Container Breakout & Host Escape"
        elif any("rev-shell" in s.stage_id for s in stages):
            scenario_name = "Interactive Reverse Shell & External C2"
        elif len(tactics_observed) == 1:
            scenario_name = f"Atomic {list(tactics_observed)[0].value} Activity"

        # Severity escalation
        escalated_sev = max_sev
        if len(tactics_observed) >= 2:
            if max_sev in (Severity.NOTICE, Severity.WARNING):
                escalated_sev = Severity.ALERT
            elif max_sev == Severity.ALERT:
                escalated_sev = Severity.CRITICAL

        if any("escape" in s.stage_id or "rev-shell" in s.stage_id for s in stages):
            escalated_sev = Severity.CRITICAL

        # Quantitative threat score (0-100)
        base_score = float(self._severity_weight(max_sev))
        stage_diversity_bonus = min(30.0, (len(tactics_observed) - 1) * 15.0) if len(tactics_observed) > 1 else 0.0
        threat_score = min(100.0, max(0.0, base_score + stage_diversity_bonus))

        # Epistemic confidence
        inferred_count = sum(1 for s in stages if s.epistemic_certainty == "INFERRED")
        epistemic_conf = 1.0 - (0.15 * min(2, inferred_count))

        first_ts = stages[0].timestamp
        last_ts = stages[-1].timestamp
        seq_id = f"seq:{host}:{int(first_ts.timestamp())}:{len(stages)}"

        sequence = HostAttackSequence(
            sequence_id=seq_id,
            host=host,
            scenario_name=scenario_name,
            first_seen=first_ts,
            last_seen=last_ts,
            stages=stages,
            threat_score=threat_score,
            escalated_severity=escalated_sev,
            epistemic_confidence=epistemic_conf,
            participating_users=sorted(list(users)),
            participating_processes=sorted(list(processes)),
            external_ips=sorted(list(ips)),
        )

        return [sequence]

    @staticmethod
    def _severity_weight(sev: Severity) -> int:
        weights = {
            Severity.CRITICAL: 75,
            Severity.ALERT: 55,
            Severity.WARNING: 35,
            Severity.NOTICE: 20,
            Severity.INFORMATIONAL: 10,
            Severity.DEBUG: 5,
        }
        return weights.get(sev, 20)

    @staticmethod
    def _parse_dt(val: Any) -> datetime:
        if isinstance(val, datetime):
            return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
        if isinstance(val, str):
            try:
                dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass
        return datetime.now(timezone.utc)

    @staticmethod
    def _generate_assessment_summary(
        host: str,
        scenario: str,
        tactics: List[str],
        stage_count: int,
        node_count: int,
        severity: Severity,
    ) -> str:
        tactics_str = ", ".join(tactics) if tactics else "None"
        return (
            f"Host Threat Assessment for {host}: Evaluated {stage_count} attack stages "
            f"across tactics [{tactics_str}]. Primary scenario: '{scenario}'. "
            f"Correlated {node_count} graph entities with escalated severity {severity.value}."
        )
