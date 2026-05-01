from datetime import datetime
import psycopg2
from psycopg2.extras import Json


DB_CONFIG = {
    "dbname": "ghosttrap",
    "user": "ghosttrap_user",
    "password": "ghosttrap@e",
    "host": "localhost",
    "port": 5432,
}


SIGNAL_MAX_WEIGHTS = {
    "system_reconnaissance": 20,
    "payload_download": 25,
    "permission_change": 10,
    "execution_attempt": 25,
    "sensitive_file_access": 30,
    "persistence_attempt": 35,
    "destructive_command": 45,
    "ssh_bruteforce": 25,
    "malware_execution_pattern": 35,
    "multi_sensor_observed": 20,
}


def get_conn():
    return psycopg2.connect(**DB_CONFIG)


def insert_raw_event(
    source,
    source_type,
    event_type,
    indicator,
    confidence=50,
    severity="medium",
    evidence=None,
    raw_data=None,
):
    evidence = evidence or {}
    raw_data = raw_data or {}

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO reputation_raw_events
                (
                    source,
                    source_type,
                    event_type,
                    indicator_type,
                    indicator,
                    confidence,
                    severity,
                    evidence,
                    raw_data,
                    observed_at
                )
                VALUES (%s, %s, %s, 'ip', %s, %s, %s, %s, %s, %s)
                RETURNING id;
                """,
                (
                    source,
                    source_type,
                    event_type,
                    indicator,
                    confidence,
                    severity,
                    Json(evidence),
                    Json(raw_data),
                    datetime.utcnow(),
                ),
            )

            return cur.fetchone()[0]


def insert_signal(
    indicator,
    source,
    signal_type,
    score_weight,
    confidence=50,
    severity="medium",
    evidence="",
    raw_event_id=None,
):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO reputation_signals
                (
                    indicator_type,
                    indicator,
                    source,
                    signal_type,
                    score_weight,
                    confidence,
                    severity,
                    evidence,
                    raw_event_id
                )
                VALUES ('ip', %s, %s, %s, %s, %s, %s, %s, %s);
                """,
                (
                    indicator,
                    source,
                    signal_type,
                    score_weight,
                    confidence,
                    severity,
                    evidence,
                    raw_event_id,
                ),
            )


def calculate_reputation(indicator):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT source, signal_type, score_weight, confidence, severity, evidence
                FROM reputation_signals
                WHERE indicator = %s;
                """,
                (indicator,),
            )

            rows = cur.fetchall()

            grouped = {}

            for source, signal_type, score_weight, confidence, severity, evidence in rows:
                if signal_type not in grouped:
                    grouped[signal_type] = {
                        "sources": set(),
                        "weight": 0,
                        "confidence": 0,
                        "severity": severity,
                        "evidence": [],
                    }

                grouped[signal_type]["sources"].add(source)
                grouped[signal_type]["weight"] = max(
                    grouped[signal_type]["weight"],
                    int(score_weight or 0),
                )
                grouped[signal_type]["confidence"] = max(
                    grouped[signal_type]["confidence"],
                    int(confidence or 0),
                )

                if evidence and evidence not in grouped[signal_type]["evidence"]:
                    grouped[signal_type]["evidence"].append(evidence)

            score = 0
            sources = set()
            evidence = []

            for signal_type, data in grouped.items():
                capped_weight = min(
                    data["weight"],
                    SIGNAL_MAX_WEIGHTS.get(signal_type, data["weight"]),
                )
                score += capped_weight
                sources.update(data["sources"])

                for item in data["evidence"][:3]:
                    evidence.append(item)

            score = min(score, 100)

            has_malware_chain = (
                "payload_download" in grouped
                and "permission_change" in grouped
                and "execution_attempt" in grouped
            )

            has_critical_signal = any(
                signal in grouped
                for signal in [
                    "malware_execution_pattern",
                    "sensitive_file_access",
                    "persistence_attempt",
                    "destructive_command",
                ]
            )

            has_strong_attack_signal = any(
                signal in grouped
                for signal in [
                    "payload_download",
                    "execution_attempt",
                    "ssh_bruteforce",
                    "multi_sensor_observed",
                ]
            )

            if score >= 70 and (has_malware_chain or has_critical_signal):
                verdict = "malicious"
                confidence_label = "high"
            elif score >= 50 and (has_malware_chain or has_strong_attack_signal):
                verdict = "malicious"
                confidence_label = "medium"
            elif score >= 30:
                verdict = "suspicious"
                confidence_label = "medium"
            elif score > 0:
                verdict = "low_risk"
                confidence_label = "low"
            else:
                verdict = "unknown"
                confidence_label = "low"

            cur.execute(
                """
                INSERT INTO reputation_scores
                (
                    indicator_type,
                    indicator,
                    score,
                    verdict,
                    confidence,
                    sources,
                    evidence,
                    last_updated
                )
                VALUES ('ip', %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (indicator_type, indicator)
                DO UPDATE SET
                    score = EXCLUDED.score,
                    verdict = EXCLUDED.verdict,
                    confidence = EXCLUDED.confidence,
                    sources = EXCLUDED.sources,
                    evidence = EXCLUDED.evidence,
                    last_updated = NOW();
                """,
                (
                    indicator,
                    score,
                    verdict,
                    confidence_label,
                    sorted(list(sources)),
                    evidence,
                ),
            )

            return {
                "indicator": indicator,
                "score": score,
                "verdict": verdict,
                "confidence": confidence_label,
                "sources": sorted(list(sources)),
                "evidence": evidence,
                "signal_types": sorted(list(grouped.keys())),
            }
def get_ip_context(indicator):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT country, city, asn, isp, org, timezone
                FROM ip_intel
                WHERE ip = %s
                LIMIT 1;
                """,
                (indicator,),
            )

            row = cur.fetchone()

            if not row:
                return {}

            return {
                "country": row[0],
                "city": row[1],
                "asn": row[2],
                "isp": row[3],
                "org": row[4],
                "timezone": row[5],
            }
