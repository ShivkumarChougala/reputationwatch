import time
from reputationwatch.engine import get_conn
from reputationwatch.sources.abuseipdb import check_ip, is_public_ip
from reputationwatch.sync_external_intel import upsert_external_intel


PROVIDER = "abuseipdb"
FRESH_HOURS = 24


def fetch_candidate_ips(limit=50):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT rs.indicator, MAX(rs.last_updated) AS last_seen
                FROM reputation_scores rs
                LEFT JOIN reputation_external_intel ei
                    ON ei.indicator = rs.indicator
                   AND ei.provider = %s
                WHERE rs.indicator_type = 'ip'
                  AND (
                        ei.updated_at IS NULL
                        OR ei.updated_at < NOW() - (%s || ' hours')::INTERVAL
                  )
                GROUP BY rs.indicator
                ORDER BY last_seen ASC
                LIMIT %s;
            """, (PROVIDER, FRESH_HOURS, limit))

            return [row[0] for row in cur.fetchall()]


def sync_abuseipdb(limit=10, sleep_seconds=2):
    ips = fetch_candidate_ips(limit)

    print(f"[+] Found {len(ips)} stale/new candidate IPs")

    if not ips:
        print("[+] No IPs need AbuseIPDB refresh")
        return

    checked = 0
    skipped = 0
    failed = 0

    for ip in ips:
        if not is_public_ip(ip):
            skipped += 1
            print(f"[-] Skip private/local IP: {ip}")
            continue

        try:
            result = check_ip(ip)

            if not result:
                skipped += 1
                print(f"[-] No result for {ip}")
                continue

            reputation = upsert_external_intel(**result)
            checked += 1

            print(
                f"[+] {ip} | abuseipdb_score={result['provider_score']} | "
                f"reports={result['total_reports']} | "
                f"final_score={reputation['score']} | "
                f"verdict={reputation['verdict']}"
            )

            time.sleep(sleep_seconds)

        except Exception as e:
            failed += 1
            print(f"[!] Failed {ip}: {e}")

    print(
        f"[+] Done | checked={checked} | skipped={skipped} | "
        f"failed={failed} | freshness={FRESH_HOURS}h"
    )


if __name__ == "__main__":
    sync_abuseipdb(limit=10, sleep_seconds=2)
