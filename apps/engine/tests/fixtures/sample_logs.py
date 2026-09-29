"""Sanitized representative log fixtures for deterministic testing."""

FIXTURE_SSH_FAILURE = (
    "2026-09-29T03:14:22.123456+00:00 secure-node sshd[14221]: Failed password for invalid user admin from 198.51.100.42 port 48212 ssh2"
)

FIXTURE_SSH_SUCCESS = (
    "2026-09-29T04:20:11.654321+00:00 secure-node sshd[14502]: Accepted publickey for secops from 203.0.113.15 port 51234 ssh2"
)

FIXTURE_SUDO_COMMAND = (
    "2026-09-29T05:12:00.001234+00:00 secure-node sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
)

FIXTURE_SUDO_FAILURE = (
    "2026-09-29T05:15:30.999888+00:00 secure-node sudo: untrusted_user : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"
)

FIXTURE_PAM_SESSION_OPEN = (
    "2026-09-29T06:01:00.100200+00:00 secure-node CRON[1890]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)"
)

FIXTURE_PAM_SESSION_CLOSE = (
    "2026-09-29T06:01:05.300400+00:00 secure-node CRON[1890]: pam_unix(cron:session): session closed for user root"
)

FIXTURE_USERADD = (
    "2026-09-29T07:10:00.500600+00:00 secure-node useradd[20101]: new user: name=backdoor, UID=1050, GID=1050, home=/home/backdoor, shell=/bin/bash"
)

FIXTURE_KERNEL_BOOT = (
    "2026-09-29T00:00:01.000000+00:00 secure-node kernel: Linux version 7.0.0-34-generic (buildd@linux) (gcc 13) #34 SMP"
)

FIXTURE_KERNEL_UFW = (
    "2026-09-29T08:22:15.111222+00:00 secure-node kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=198.51.100.99 DST=192.168.1.100 PROTO=TCP SPT=44521 DPT=22"
)

FIXTURE_KERNEL_SEGFAULT = (
    "2026-09-29T09:15:40.444555+00:00 secure-node kernel: suspicious_daemon[3120]: segfault at 00007ffe812 ip 00007ffe812 sp 00007ffe810 error 4"
)

FIXTURE_GENERIC_SYSLOG = (
    "2026-09-29T10:00:00.000000+00:00 secure-node systemd[1]: Started Daily apt upgrade and clean activities."
)

FIXTURE_MALFORMED = (
    "\x1b[31;1mCRITICAL\x1b[0m \x00\x00 Unknown raw binary buffer with weird control chars \r\n"
)
