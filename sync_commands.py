from reputationwatch.engine import (
    get_conn,
    insert_raw_event,
    insert_signal,
    calculate_reputation,
)


RECON_CMDS = [
    "uname", "whoami", "id", "hostname", "pwd", "ls",
    "ps ", "ps aux", "top", "cat /proc", "lscpu", "lsb_release"
]

ENV_DISCOVERY_CMDS = [
    "env", "printenv", "set", "mount", "df", "free", "uptime",
    "history", "last", "w", "users"
]

NETWORK_RECON_CMDS = [
    "netstat", "ss ", "ip addr", "ip a", "ifconfig",
    "route", "iptables", "nmap", "masscan", "ssh -v", "ssh -V"
]

ROUTER_RECON_CMDS = [
    "/ip cloud print", "/system", "/interface", "/tool"
]

LOGIN_TEST_CMDS = [
    "echo -n login_success", "auth_ok", "login_success"
]

DOWNLOAD_CMDS = [
    "wget", "curl", "tftp", "ftp", "scp", "rsync"
]

SENSITIVE_FILES = [
    "/etc/passwd", "/etc/shadow", "authorized_keys", ".ssh", "id_rsa",
    "/root", "/home", "/var/log"
]

PERSISTENCE_CMDS = [
    "crontab", "systemctl enable", "rc.local", ".bashrc",
    "/etc/init.d", "authorized_keys", "ssh-keygen"
]

EVASION_CMDS = [
    "histfile=/dev/null", "histsave=/dev/null",
    "unset histfile", "unset histsave",
    "history -c", ">/dev/null", "2>/dev/null", "nohup"
]

DESTRUCTIVE_CMDS = [
    "rm -rf", "rm -fr", "rm -r", "rm -f", "rm /",
    "rm -rf /", "rm -rf /*", "--no-preserve-root",
    "mkfs", "dd if=", ":(){"
]


def ensure_sync_state():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reputation_sync_state (
                    name TEXT PRIMARY KEY,
                    last_id BIGINT NOT NULL DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)

            cur.execute("""
                INSERT INTO reputation_sync_state (name, last_id)
                VALUES ('commands_sync', 0)
                ON CONFLICT (name) DO NOTHING;
            """)


def get_last_processed_id():
    ensure_sync_state()

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT last_id
                FROM reputation_sync_state
                WHERE name = 'commands_sync';
            """)
            row = cur.fetchone()
            return row[0] if row else 0


def update_last_processed_id(last_id):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO reputation_sync_state (name, last_id, updated_at)
                VALUES ('commands_sync', %s, NOW())
                ON CONFLICT (name)
                DO UPDATE SET
                    last_id = EXCLUDED.last_id,
                    updated_at = NOW();
            """, (last_id,))


def fetch_new_commands(limit=500):
    last_id = get_last_processed_id()

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, HOST(src_ip), command, cwd, timestamp
                FROM commands
                WHERE id > %s
                  AND src_ip IS NOT NULL
                  AND command IS NOT NULL
                ORDER BY id ASC
                LIMIT %s;
            """, (last_id, limit))

            return cur.fetchall(), last_id


def signal_exists(ip, signal_type, evidence):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 1
                FROM reputation_signals
                WHERE indicator = %s
                  AND source = 'ghosttrap'
                  AND signal_type = %s
                  AND evidence = %s
                LIMIT 1;
            """, (ip, signal_type, evidence))

            return cur.fetchone() is not None


def normalize_command(command):
    return " ".join((command or "").lower().strip().split())


def is_shell_execution(cmd):
    if any(x in cmd for x in RECON_CMDS):
        return False

    if cmd.startswith("cd "):
        return False

    if cmd.startswith("ssh "):
        return False

    if cmd.startswith("./") or " ./" in cmd:
        return True

    if cmd.startswith("bash ") or cmd.startswith("sh "):
        return True

    if " bash " in cmd or " sh " in cmd:
        return True

    if "| sh" in cmd or "| bash" in cmd:
        return True

    return False


def classify_command(command):
    cmd = normalize_command(command)
    signals = []

    if any(x.lower() in cmd for x in LOGIN_TEST_CMDS):
        signals.append((
            "login_validation",
            5,
            "low",
            "Login validation command observed"
        ))

    if any(x.lower() in cmd for x in RECON_CMDS):
        signals.append((
            "system_reconnaissance",
            10,
            "medium",
            "System reconnaissance command observed"
        ))

    if any(x.lower() in cmd for x in ENV_DISCOVERY_CMDS):
        signals.append((
            "environment_discovery",
            10,
            "medium",
            "Environment discovery command observed"
        ))

    if any(x.lower() in cmd for x in NETWORK_RECON_CMDS):
        signals.append((
            "network_reconnaissance",
            15,
            "medium",
            "Network reconnaissance command observed"
        ))

    if any(x.lower() in cmd for x in ROUTER_RECON_CMDS):
        signals.append((
            "routeros_reconnaissance",
            15,
            "medium",
            "RouterOS style reconnaissance command observed"
        ))

    if any(x.lower() in cmd for x in EVASION_CMDS):
        signals.append((
            "history_evasion",
            20,
            "high",
            "Shell history or output evasion observed"
        ))

    if cmd.startswith("cd "):
        signals.append((
            "shell_navigation",
            5,
            "low",
            "Shell navigation command observed"
        ))

    if any(x.lower() in cmd for x in DOWNLOAD_CMDS):
        signals.append((
            "payload_download",
            25,
            "high",
            "Payload download command observed"
        ))

    if "chmod" in cmd:
        signals.append((
            "permission_change",
            10,
            "medium",
            "Permission change command observed"
        ))

    if is_shell_execution(cmd):
        signals.append((
            "execution_attempt",
            25,
            "high",
            "Script or binary execution attempt observed"
        ))

    if any(x.lower() in cmd for x in SENSITIVE_FILES):
        signals.append((
            "sensitive_file_access",
            30,
            "high",
            "Sensitive file access attempt observed"
        ))

    if any(x.lower() in cmd for x in PERSISTENCE_CMDS):
        signals.append((
            "persistence_attempt",
            35,
            "critical",
            "Persistence attempt observed"
        ))

    if (
        any(x.lower() in cmd for x in DESTRUCTIVE_CMDS)
        or cmd.startswith("rm ")
        or " rm " in cmd
    ):
        signals.append((
            "destructive_command",
            45,
            "critical",
            "Destructive command observed"
        ))

    if not signals:
        signals.append((
            "unclassified_command_observed",
            3,
            "low",
            "Unclassified attacker command observed"
        ))

    return signals


def sync_commands(limit=500):
    rows, last_id = fetch_new_commands(limit)

    print(f"[+] Last processed command id: {last_id}")
    print(f"[+] Found {len(rows)} new command rows")

    if not rows:
        print("[+] No new commands to process")
        return

    processed_ids = []

    for command_id, ip, command, cwd, timestamp in rows:
        processed_ids.append(command_id)
        signals = classify_command(command)

        raw_event_id = insert_raw_event(
            source="ghosttrap",
            source_type="first_party",
            event_type="command_observed",
            indicator=ip,
            confidence=90,
            severity="medium",
            evidence={
                "command_id": command_id,
                "command": command,
                "normalized_command": normalize_command(command),
                "cwd": cwd,
                "timestamp": str(timestamp),
                "classified": bool(signals),
                "signal_count": len(signals),
            },
            raw_data={
                "source_table": "commands",
                "command_id": command_id,
            },
        )

        added = 0

        for signal_type, weight, severity, reason in signals:
            evidence = f"{reason}: {command}"

            if signal_exists(ip, signal_type, evidence):
                continue

            insert_signal(
                indicator=ip,
                source="ghosttrap",
                signal_type=signal_type,
                score_weight=weight,
                confidence=90,
                severity=severity,
                evidence=evidence,
                raw_event_id=raw_event_id,
            )

            added += 1

        result = calculate_reputation(ip)

        print(
            f"[+] id={command_id} | {ip} | raw_saved=yes | "
            f"signals={len(signals)} | added={added} | "
            f"score={result['score']} | verdict={result['verdict']} | "
            f"cmd='{command[:70]}'"
        )

    max_id = max(processed_ids)
    update_last_processed_id(max_id)

    print(f"[+] Updated last processed command id: {max_id}")


if __name__ == "__main__":
    sync_commands(limit=500)
