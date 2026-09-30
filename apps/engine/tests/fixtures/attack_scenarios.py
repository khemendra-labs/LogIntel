"""Deterministic attack scenario fixtures for LogIntel M2.10 replay verification."""

from datetime import datetime, timedelta, timezone
from typing import List

from logintel.models import (
    Actor,
    CanonicalEvent,
    EventType,
    Network,
    Outcome,
    Process,
    Severity,
)

BASE_TIME = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)


def create_ssh_bruteforce_scenario(
    base_time: datetime = BASE_TIME,
    attacker_ip: str = "203.0.113.100",
    host: str = "srv-edge-01",
) -> List[CanonicalEvent]:
    """6 SSH authentication failures within 60 seconds from same attacker IP."""
    events = []
    for i in range(6):
        t = base_time + timedelta(seconds=i * 10)
        events.append(
            CanonicalEvent(
                id=f"ev-ssh-bf-{i+1:02d}",
                timestamp=t,
                ingested_at=t,
                host=host,
                source="/var/log/auth.log",
                event_type=EventType.AUTH_LOGIN_FAILURE,
                severity=Severity.NOTICE,
                actor=Actor(username=f"user_{i}"),
                process=Process(name="sshd", pid=1000 + i),
                network=Network(src_ip=attacker_ip, src_port=40000 + i, dst_port=22, protocol="tcp"),
                action="ssh_login",
                outcome=Outcome.FAILURE,
                summary=f"Failed SSH password for user_{i} from {attacker_ip}",
                raw_message=f"Failed password for user_{i} from {attacker_ip} port {40000+i} ssh2",
                parser="ssh_failure",
            )
        )
    return events


def create_privilege_escalation_scenario(
    base_time: datetime = BASE_TIME,
    username: str = "bob",
    host: str = "srv-app-02",
) -> List[CanonicalEvent]:
    """Sudo failure burst followed by unauthorized sudo and root shell."""
    events = []
    # 3 sudo failures in 30 seconds
    for i in range(3):
        t = base_time + timedelta(seconds=i * 10)
        events.append(
            CanonicalEvent(
                id=f"ev-sudo-fail-{i+1:02d}",
                timestamp=t,
                ingested_at=t,
                host=host,
                source="/var/log/auth.log",
                event_type=EventType.PRIVILEGE_ELEVATION_FAILURE,
                severity=Severity.WARNING,
                actor=Actor(username=username, uid=1002),
                process=Process(name="sudo", command_line="/usr/bin/sudo /bin/cat /etc/shadow"),
                action="sudo_command",
                outcome=Outcome.FAILURE,
                summary=f"Sudo authentication failure for user '{username}'",
                raw_message=f"{username} : 1 incorrect password attempt ; PWD=/home/{username} ; USER=root ; COMMAND=/bin/cat /etc/shadow",
                parser="sudo_failure",
            )
        )

    # 1 unauthorized sudo
    t_unauth = base_time + timedelta(seconds=40)
    events.append(
        CanonicalEvent(
            id="ev-sudo-unauth-01",
            timestamp=t_unauth,
            ingested_at=t_unauth,
            host=host,
            source="/var/log/auth.log",
            event_type=EventType.PRIVILEGE_ELEVATION_FAILURE,
            severity=Severity.ALERT,
            actor=Actor(username=username, uid=1002),
            process=Process(name="sudo", command_line="/usr/bin/sudo -l"),
            action="sudo_command",
            outcome=Outcome.FAILURE,
            summary=f"Sudo privilege elevation failure for user '{username}': user NOT in sudoers",
            raw_message=f"{username} : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/{username} ; USER=root ; COMMAND=/usr/bin/sudo -l",
            parser="sudo_privilege",
        )
    )

    # 1 sudo root shell
    t_shell = base_time + timedelta(seconds=60)
    events.append(
        CanonicalEvent(
            id="ev-sudo-shell-01",
            timestamp=t_shell,
            ingested_at=t_shell,
            host=host,
            source="/var/log/auth.log",
            event_type=EventType.SUDO_COMMAND,
            severity=Severity.ALERT,
            actor=Actor(username=username, uid=1002),
            process=Process(name="sudo", command_line="/bin/bash"),
            action="sudo_command",
            outcome=Outcome.SUCCESS,
            summary=f"Privilege elevation command by '{username}': sudo /bin/bash",
            raw_message=f"{username} : TTY=pts/1 ; PWD=/home/{username} ; USER=root ; COMMAND=/bin/bash",
            parser="sudo_command",
        )
    )

    return events


def create_recon_and_segfault_scenario(
    base_time: datetime = BASE_TIME,
    host: str = "srv-db-01",
) -> List[CanonicalEvent]:
    """Reconnaissance tools execution + AppArmor denial + Segfault burst."""
    events = []

    # 1 reconnaissance tool: nmap via sudo
    t_recon = base_time + timedelta(seconds=5)
    events.append(
        CanonicalEvent(
            id="ev-recon-01",
            timestamp=t_recon,
            ingested_at=t_recon,
            host=host,
            source="/var/log/auth.log",
            event_type=EventType.SUDO_COMMAND,
            severity=Severity.NOTICE,
            actor=Actor(username="attacker"),
            process=Process(name="sudo", command_line="/usr/bin/nmap -sS -p- 192.168.1.0/24"),
            action="sudo_command",
            outcome=Outcome.SUCCESS,
            summary="Network reconnaissance tool executed via sudo: nmap",
            raw_message="nmap -sS -p- 192.168.1.0/24 executed by attacker",
            parser="sudo_command",
        )
    )

    # 1 AppArmor denial
    t_aa = base_time + timedelta(seconds=15)
    events.append(
        CanonicalEvent(
            id="ev-apparmor-01",
            timestamp=t_aa,
            ingested_at=t_aa,
            host=host,
            source="/var/log/kern.log",
            event_type=EventType.SECURITY_ACCESS_DENIED,
            severity=Severity.WARNING,
            actor=Actor(username="root"),
            process=Process(name="nginx", pid=2240),
            action="apparmor_denied",
            outcome=Outcome.FAILURE,
            summary="AppArmor access denied: apparmor='DENIED' operation='open' profile='/usr/sbin/nginx' name='/etc/shadow'",
            raw_message="audit: type=1400 apparmor='DENIED' operation='open' profile='/usr/sbin/nginx' name='/etc/shadow' pid=2240 comm='nginx' requested_mask='r' denied_mask='r'",
            parser="linux_kernel",
            metadata={"apparmor_operation": "open", "profile": "/usr/sbin/nginx"},
        )
    )

    # 5 segfaults within 20 seconds for vulnerable_app
    for i in range(5):
        t = base_time + timedelta(seconds=20 + i * 3)
        events.append(
            CanonicalEvent(
                id=f"ev-segfault-{i+1:02d}",
                timestamp=t,
                ingested_at=t,
                host=host,
                source="/var/log/kern.log",
                event_type=EventType.KERNEL_MESSAGE,
                severity=Severity.WARNING,
                actor=Actor(),
                process=Process(name="vulnerable_app", pid=5000 + i),
                action="segmentation_fault",
                outcome=Outcome.FAILURE,
                summary="Application crash: segfault in 'vulnerable_app' (PID: 5000) at memory address 0xdeadbeef",
                raw_message=f"vulnerable_app[{5000+i}]: segfault at 0000000000000000 ip 00007f99 sp 00007ffd error 4 in vulnerable_app[400000+1000]",
                parser="kernel_segfault",
            )
        )

    return events


def create_benign_administrative_scenario(
    base_time: datetime = BASE_TIME,
    host: str = "srv-admin-01",
) -> List[CanonicalEvent]:
    """Standard legitimate admin login, safe systemctl command, and session logout (Negative Baseline)."""
    events = []

    # 1. Successful SSH login
    t1 = base_time
    events.append(
        CanonicalEvent(
            id="ev-benign-01",
            timestamp=t1,
            ingested_at=t1,
            host=host,
            source="/var/log/auth.log",
            event_type=EventType.AUTH_LOGIN_SUCCESS,
            severity=Severity.INFORMATIONAL,
            actor=Actor(username="sysadmin", uid=1000),
            process=Process(name="sshd", pid=3100),
            network=Network(src_ip="192.168.1.50", src_port=55122, dst_port=22, protocol="tcp"),
            action="ssh_login",
            outcome=Outcome.SUCCESS,
            summary="Accepted publickey for sysadmin from 192.168.1.50 port 55122 ssh2",
            raw_message="Accepted publickey for sysadmin from 192.168.1.50 port 55122 ssh2",
            parser="ssh_success",
        )
    )

    # 2. Benign sudo command: systemctl restart nginx
    t2 = base_time + timedelta(seconds=20)
    events.append(
        CanonicalEvent(
            id="ev-benign-02",
            timestamp=t2,
            ingested_at=t2,
            host=host,
            source="/var/log/auth.log",
            event_type=EventType.PRIVILEGE_ELEVATION_SUCCESS,
            severity=Severity.NOTICE,
            actor=Actor(username="sysadmin", uid=1000),
            process=Process(name="sudo", command_line="sudo /bin/systemctl restart nginx"),
            action="sudo_command",
            outcome=Outcome.SUCCESS,
            summary="Privilege elevation command by 'sysadmin': sudo /bin/systemctl restart nginx",
            raw_message="sysadmin : TTY=pts/0 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/bin/systemctl restart nginx",
            parser="sudo_command",
        )
    )

    # 3. Session logout
    t3 = base_time + timedelta(seconds=45)
    events.append(
        CanonicalEvent(
            id="ev-benign-03",
            timestamp=t3,
            ingested_at=t3,
            host=host,
            source="/var/log/auth.log",
            event_type=EventType.SESSION_CLOSE,
            severity=Severity.INFORMATIONAL,
            actor=Actor(username="sysadmin", uid=1000),
            process=Process(name="sshd", pid=3100),
            action="session_close",
            outcome=Outcome.SUCCESS,
            summary="pam_unix(sshd:session): session closed for user sysadmin",
            raw_message="pam_unix(sshd:session): session closed for user sysadmin",
            parser="pam_session",
        )
    )

    return events


def create_auth_attacks_scenario(
    base_time: datetime = BASE_TIME,
    host: str = "srv-auth-01",
) -> List[CanonicalEvent]:
    """Covers auth.invalid_user, auth.root_login, auth.password_spray, auth.repeated_failures."""
    events = []

    # 1. auth.root_login (direct root login via ssh)
    t_root = base_time + timedelta(seconds=2)
    events.append(
        CanonicalEvent(
            id="ev-auth-root-01",
            timestamp=t_root,
            ingested_at=t_root,
            host=host,
            source="/var/log/auth.log",
            event_type=EventType.AUTH_LOGIN_SUCCESS,
            severity=Severity.WARNING,
            actor=Actor(username="root", uid=0),
            process=Process(name="sshd", pid=8001),
            network=Network(src_ip="203.0.113.88", src_port=52341, dst_port=22, protocol="tcp"),
            action="ssh_login",
            outcome=Outcome.SUCCESS,
            summary="Accepted password for root from 203.0.113.88 port 52341 ssh2",
            raw_message="Accepted password for root from 203.0.113.88 port 52341 ssh2",
            parser="openssh_auth",
        )
    )

    # 2. auth.invalid_user (3 failures with invalid user from 198.51.100.33)
    for i in range(3):
        t_inv = base_time + timedelta(seconds=10 + i * 10)
        events.append(
            CanonicalEvent(
                id=f"ev-auth-inv-{i+1:02d}",
                timestamp=t_inv,
                ingested_at=t_inv,
                host=host,
                source="/var/log/auth.log",
                event_type=EventType.AUTH_LOGIN_FAILURE,
                severity=Severity.ALERT,
                actor=Actor(username=f"fakeuser_{i}"),
                process=Process(name="sshd", pid=8100 + i),
                network=Network(src_ip="198.51.100.33", src_port=53000 + i, dst_port=22, protocol="tcp"),
                action="ssh_login",
                outcome=Outcome.FAILURE,
                summary=f"Failed password for invalid user fakeuser_{i} from 198.51.100.33 port {53000+i} ssh2",
                raw_message=f"Failed password for invalid user fakeuser_{i} from 198.51.100.33 port {53000+i} ssh2",
                parser="ssh_failure",
            )
        )

    # 3. auth.repeated_failures (5 failures for user 'alice' on srv-auth-01)
    for i in range(5):
        t_rep = base_time + timedelta(seconds=50 + i * 10)
        events.append(
            CanonicalEvent(
                id=f"ev-auth-rep-{i+1:02d}",
                timestamp=t_rep,
                ingested_at=t_rep,
                host=host,
                source="/var/log/auth.log",
                event_type=EventType.AUTH_LOGIN_FAILURE,
                severity=Severity.WARNING,
                actor=Actor(username="alice", uid=1001),
                process=Process(name="sshd", pid=8200 + i),
                network=Network(src_ip=f"203.0.113.{50+i}", src_port=54000 + i, dst_port=22, protocol="tcp"),
                action="ssh_login",
                outcome=Outcome.FAILURE,
                summary="Failed password for alice from disparate IPs",
                raw_message=f"Failed password for alice from 203.0.113.{50+i} port {54000+i} ssh2",
                parser="ssh_failure",
            )
        )

    # 4. auth.password_spray (10 failures from single src_ip 198.51.100.99 across distinct users)
    for i in range(10):
        t_spray = base_time + timedelta(seconds=120 + i * 5)
        events.append(
            CanonicalEvent(
                id=f"ev-auth-spray-{i+1:02d}",
                timestamp=t_spray,
                ingested_at=t_spray,
                host=host,
                source="/var/log/auth.log",
                event_type=EventType.AUTH_LOGIN_FAILURE,
                severity=Severity.CRITICAL,
                actor=Actor(username=f"target_user_{i}"),
                process=Process(name="sshd", pid=8300 + i),
                network=Network(src_ip="198.51.100.99", src_port=55000 + i, dst_port=22, protocol="tcp"),
                action="ssh_login",
                outcome=Outcome.FAILURE,
                summary=f"Failed password for target_user_{i} from 198.51.100.99 port {55000+i} ssh2",
                raw_message=f"Failed password for target_user_{i} from 198.51.100.99 port {55000+i} ssh2",
                parser="ssh_failure",
            )
        )

    return events


def create_account_tampering_scenario(
    base_time: datetime = BASE_TIME,
    host: str = "srv-iam-01",
) -> List[CanonicalEvent]:
    """Covers account.root_creation and account.deletion_burst."""
    events = []

    # 1. account.root_creation (user created with UID 0)
    t_root = base_time + timedelta(seconds=5)
    events.append(
        CanonicalEvent(
            id="ev-acct-root-01",
            timestamp=t_root,
            ingested_at=t_root,
            host=host,
            source="/var/log/auth.log",
            event_type=EventType.USER_CREATE,
            severity=Severity.CRITICAL,
            actor=Actor(username="backdoor_admin", uid=0),
            process=Process(name="useradd", executable="/usr/sbin/useradd"),
            action="account_created",
            outcome=Outcome.SUCCESS,
            summary="New user account created with UID 0: backdoor_admin",
            raw_message="useradd[9001]: new user: name=backdoor_admin, UID=0, GID=0",
            parser="user_management",
        )
    )

    # 2. account.deletion_burst (3 user deletions within 60s)
    for i in range(3):
        t_del = base_time + timedelta(seconds=20 + i * 10)
        events.append(
            CanonicalEvent(
                id=f"ev-acct-del-{i+1:02d}",
                timestamp=t_del,
                ingested_at=t_del,
                host=host,
                source="/var/log/auth.log",
                event_type=EventType.USER_DELETE,
                severity=Severity.WARNING,
                actor=Actor(username=f"victim_user_{i}"),
                process=Process(name="userdel", executable="/usr/sbin/userdel"),
                action="account_deleted",
                outcome=Outcome.SUCCESS,
                summary=f"User account deleted: victim_user_{i}",
                raw_message=f"userdel[9100]: delete user 'victim_user_{i}'",
                parser="user_management",
            )
        )

    return events


def create_network_intrusion_scenario(
    base_time: datetime = BASE_TIME,
    host: str = "gateway-gw-01",
) -> List[CanonicalEvent]:
    """Covers network.firewall_scan_burst, network.sensitive_port_probe, network.threat_intel_ioc_match."""
    events = []

    # 1. network.threat_intel_ioc_match (event matches known malicious indicator 198.51.100.66)
    t_ioc = base_time + timedelta(seconds=5)
    events.append(
        CanonicalEvent(
            id="ev-net-ioc-01",
            timestamp=t_ioc,
            ingested_at=t_ioc,
            host=host,
            source="/var/log/syslog",
            event_type=EventType.SYSTEM_GENERIC,
            severity=Severity.CRITICAL,
            actor=Actor(),
            process=Process(),
            network=Network(src_ip="198.51.100.66", dst_port=443, protocol="tcp"),
            action="connection_attempt",
            outcome=Outcome.ATTEMPT,
            summary="Outbound connection to threat actor infrastructure: 198.51.100.66",
            raw_message="threat intel alert: communication with 198.51.100.66",
            parser="generic_syslog",
            iocs=["198.51.100.66"],
        )
    )

    # 2. network.sensitive_port_probe (UFW Firewall blocked connection to port 3389)
    t_probe = base_time + timedelta(seconds=10)
    events.append(
        CanonicalEvent(
            id="ev-net-probe-01",
            timestamp=t_probe,
            ingested_at=t_probe,
            host=host,
            source="/var/log/ufw.log",
            event_type=EventType.KERNEL_MESSAGE,
            severity=Severity.WARNING,
            actor=Actor(),
            process=Process(),
            network=Network(src_ip="203.0.113.77", dst_port=3389, protocol="tcp"),
            action="firewall_block",
            outcome=Outcome.FAILURE,
            summary="[UFW BLOCK] UFW Firewall blocked incoming packet to port 3389",
            raw_message="[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.77 DST=192.168.1.1 PROTO=TCP SPT=43210 DPT=3389",
            parser="ufw_firewall",
        )
    )

    # 3. network.firewall_scan_burst (5 UFW blocks from 203.0.113.99 within 60s)
    for i in range(5):
        t_burst = base_time + timedelta(seconds=20 + i * 5)
        events.append(
            CanonicalEvent(
                id=f"ev-net-burst-{i+1:02d}",
                timestamp=t_burst,
                ingested_at=t_burst,
                host=host,
                source="/var/log/ufw.log",
                event_type=EventType.KERNEL_MESSAGE,
                severity=Severity.ALERT,
                actor=Actor(),
                process=Process(),
                network=Network(src_ip="203.0.113.99", dst_port=1000 + i, protocol="tcp"),
                action="firewall_block",
                outcome=Outcome.FAILURE,
                summary=f"[UFW BLOCK] UFW Firewall blocked probe on port {1000+i}",
                raw_message=f"[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.99 DST=192.168.1.1 PROTO=TCP SPT=40000 DPT={1000+i}",
                parser="ufw_firewall",
            )
        )

    return events

