from psycopg2.extras import Json
from reputationwatch.engine import (
    get_conn,
    insert_raw_event,
    insert_signal,
    calculate_reputation,
)


PROVIDER_SIGNAL_MAP = {
    "abuseipdb": {
        "malicious": ("external_abuse_report", 45, "high"),
        "suspicious": ("external_suspicious_report", 25, "medium"),
        "low_risk": ("external_low_risk_report", 5, "low"),
        "unknown": ("external_reputation_observed", 0, "low"),
    },
    "virustotal": {
        "malicious": ("external_malware_reputation", 35, "high"),
        "suspicious": ("external_suspicious_reputation", 20, "medium"),
        "low_risk": ("external_low_risk_report", 5, "low"),
        "unknown": ("external_reputation_observed", 0, "low"),
    },
    "greynoise": {
        "malicious": ("external_known_bad_scanner", 30, "high"),
        "suspicious": ("external_known_scanner", 15, "medium"),
        "low_risk": ("external_noise_seen", 5, "low"),
        "unknown": ("external_reputation_observed", 0, "low"),
    },
}


def normalize_verdict(provider_score):
    score = int(provider_score or 0)

    if score >= 75:
        return "malicious"
    if score >= 35:
        return "suspicious"
    if score > 0:
        return "low_risk"
    return "unknown"


def build_external_evidence(
    provider,
    provider_score,
    provider_verdict,
    categories,
    total_reports,
    raw_response,
):
    latest_comment = ""

    if raw_response and isinstance(raw_response, dict):
        reports = raw_response.get("reports") or []
        if reports:
            latest_comment = reports[0].get("comment") or ""

    if latest_comment:
        latest_comment = " ".join(latest_comment.split())
        latest_comment = latest_comment[:220]

        return (
            f"{provider} verdict={provider_verdict}, "
            f"score={provider_score}, reports={total_reports}, "
            f"categories={','.join(categories)} | "
            f"latest_report='{latest_comment}'"
        )

    return (
        f"{provider} verdict={provider_verdict}, "
        f"score={provider_score}, reports={total_reports}, "
        f"categories={','.join(categories)}"
    )


def signal_exists(indicator, source, signal_type, evidence):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 1
                FROM reputation_signals
                WHERE indicator = %s
                  AND source = %s
                  AND signal_type = %s
                  AND evidence = %s
                LIMIT 1;
            """, (indicator, source, signal_type, evidence))

            return cur.fetchone() is not None


def add_signal_once(
    indicator,
    source,
    signal_type,
    score_weight,
    confidence,
    severity,
    evidence,
    raw_event_id,
):
    if signal_exists(indicator, source, signal_type, evidence):
        return False

    insert_signal(
        indicator=indicator,
        source=source,
        signal_type=signal_type,
        score_weight=score_weight,
        confidence=confidence,
        severity=severity,
        evidence=evidence,
        raw_event_id=raw_event_id,
    )

    return True


def upsert_external_intel(
    indicator,
    provider,
    provider_score=0,
    provider_verdict=None,
    categories=None,
    country_code=None,
    usage_type=None,
    isp=None,
    domain=None,
    total_reports=0,
    last_reported_at=None,
    raw_response=None,
):
    provider = provider.lower().strip()
    provider_score = int(provider_score or 0)
    total_reports = int(total_reports or 0)
    provider_verdict = provider_verdict or normalize_verdict(provider_score)
    categories = [str(c) for c in (categories or [])]
    raw_response = raw_response or {}

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO reputation_external_intel
                (
                    indicator,
                    provider,
                    provider_score,
                    provider_verdict,
                    categories,
                    country_code,
                    usage_type,
                    isp,
                    domain,
                    total_reports,
                    last_reported_at,
                    raw_response,
                    updated_at
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
                ON CONFLICT (provider, indicator)
                DO UPDATE SET
                    provider_score = EXCLUDED.provider_score,
                    provider_verdict = EXCLUDED.provider_verdict,
                    categories = EXCLUDED.categories,
                    country_code = EXCLUDED.country_code,
                    usage_type = EXCLUDED.usage_type,
                    isp = EXCLUDED.isp,
                    domain = EXCLUDED.domain,
                    total_reports = EXCLUDED.total_reports,
                    last_reported_at = EXCLUDED.last_reported_at,
                    raw_response = EXCLUDED.raw_response,
                    updated_at = NOW()
                RETURNING id;
            """, (
                indicator,
                provider,
                provider_score,
                provider_verdict,
                categories,
                country_code,
                usage_type,
                isp,
                domain,
                total_reports,
                last_reported_at,
                Json(raw_response),
            ))

            external_id = cur.fetchone()[0]

    raw_event_id = insert_raw_event(
        source=provider,
        source_type="external_intel",
        event_type="external_ip_reputation",
        indicator=indicator,
        confidence=80,
        severity="high" if provider_verdict == "malicious" else "medium",
        evidence={
            "provider": provider,
            "provider_score": provider_score,
            "provider_verdict": provider_verdict,
            "categories": categories,
            "total_reports": total_reports,
            "external_intel_id": external_id,
        },
        raw_data=raw_response,
    )

    signal_type, weight, severity = PROVIDER_SIGNAL_MAP.get(provider, {}).get(
        provider_verdict,
        ("external_reputation_observed", 0, "low")
    )

    evidence = build_external_evidence(
        provider=provider,
        provider_score=provider_score,
        provider_verdict=provider_verdict,
        categories=categories,
        total_reports=total_reports,
        raw_response=raw_response,
    )

    add_signal_once(
        indicator=indicator,
        source=provider,
        signal_type=signal_type,
        score_weight=weight,
        confidence=80,
        severity=severity,
        evidence=evidence,
        raw_event_id=raw_event_id,
    )

    if (
        provider == "abuseipdb"
        and provider_score >= 90
        and total_reports >= 100
    ):
        boost_evidence = (
            f"High-confidence AbuseIPDB reputation: "
            f"score={provider_score}, reports={total_reports}"
        )

        add_signal_once(
            indicator=indicator,
            source=provider,
            signal_type="external_high_confidence_abuse",
            score_weight=30,
            confidence=90,
            severity="high",
            evidence=boost_evidence,
            raw_event_id=raw_event_id,
        )

    result = calculate_reputation(indicator)
    return result


if __name__ == "__main__":
    result = upsert_external_intel(
        indicator="8.8.8.8",
        provider="abuseipdb",
        provider_score=0,
        provider_verdict="unknown",
        categories=["test"],
        total_reports=1,
        raw_response={"demo": True}
    )
    print(result)
