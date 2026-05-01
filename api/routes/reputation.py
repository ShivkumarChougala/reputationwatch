from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from psycopg2.extras import Json
from reputationwatch.engine import calculate_reputation, get_ip_context
from fastapi.responses import PlainTextResponse

from database.db import get_db_connection


router = APIRouter(prefix="/reputation", tags=["ReputationWatch"])


class IPReport(BaseModel):
    indicator: str
    category: str = "unknown"
    confidence: int = 50
    severity: str = "medium"
    evidence: Optional[str] = ""
    source_url: Optional[str] = None
    reporter_name: Optional[str] = None
    reporter_email: Optional[str] = None


def build_explanation(score, verdict, signals):
    if not signals:
        return "No behavior signals found for this indicator."

    critical = [s for s in signals if s["severity"] == "critical"]
    high = [s for s in signals if s["severity"] == "high"]

    names = [s["signal_type"].replace("_", " ") for s in signals[:5]]

    if verdict == "malicious":
        return (
            "This IP is classified as malicious because it showed strong attacker behavior: "
            + ", ".join(names)
            + "."
        )

    if verdict == "suspicious":
        return (
            "This IP is suspicious because it performed multiple risky behaviors: "
            + ", ".join(names)
            + "."
        )

    if high or critical:
        return (
            "This IP has low total score, but high-risk behavior was observed: "
            + ", ".join(names)
            + "."
        )

    return (
        "This IP has limited reputation activity. Observed behavior includes: "
        + ", ".join(names)
        + "."
    )


@router.get("/top")
def top_reputation(limit: int = Query(20, ge=1, le=100)):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            indicator,
            score,
            verdict,
            confidence,
            sources,
            evidence,
            last_updated
        FROM reputation_scores
        ORDER BY score DESC, last_updated DESC
        LIMIT %s;
    """, (limit,))

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return {
        "data": rows,
        "meta": {
            "limit": limit,
            "count": len(rows)
        }
    }


@router.get("/{indicator}")
def lookup_reputation(indicator: str):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            indicator,
            score,
            verdict,
            confidence,
            sources,
            evidence,
            last_updated
        FROM reputation_scores
        WHERE indicator = %s;
    """, (indicator,))

    row = cur.fetchone()

    cur.close()
    conn.close()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Indicator not found in ReputationWatch"
        )

    return {"data": row}


@router.get("/{indicator}/explain")
def explain_reputation(indicator: str):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            indicator,
            score,
            verdict,
            confidence,
            sources,
            evidence,
            last_updated
        FROM reputation_scores
        WHERE indicator = %s;
    """, (indicator,))

    score_row = cur.fetchone()

    if not score_row:
        cur.close()
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Indicator not found in ReputationWatch"
        )

    cur.execute("""
        SELECT
            signal_type,
            severity,
            score_weight,
            confidence,
            source,
            evidence,
            raw_event_id
        FROM reputation_signals
        WHERE indicator = %s
        ORDER BY score_weight DESC, id DESC;
    """, (indicator,))

    signals = cur.fetchall()

    cur.close()
    conn.close()

    explanation = build_explanation(
        score_row["score"],
        score_row["verdict"],
        signals
    )

    return {
        "data": {
            "indicator": score_row["indicator"],
            "score": score_row["score"],
            "verdict": score_row["verdict"],
            "confidence": score_row["confidence"],
            "sources": score_row["sources"],
            "last_updated": score_row["last_updated"],
            "explanation": explanation,
            "summary": {
                "total_signals": len(signals),
                "critical_signals": len([s for s in signals if s["severity"] == "critical"]),
                "high_signals": len([s for s in signals if s["severity"] == "high"]),
                "medium_signals": len([s for s in signals if s["severity"] == "medium"]),
                "low_signals": len([s for s in signals if s["severity"] == "low"]),
            },
            "signals": signals,
            "evidence": score_row["evidence"],
        }
    }


@router.get("/signals/recent")
def recent_signals(limit: int = Query(25, ge=1, le=100)):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            indicator,
            signal_type,
            severity,
            score_weight,
            confidence,
            source,
            evidence,
            raw_event_id
        FROM reputation_signals
        ORDER BY id DESC
        LIMIT %s;
    """, (limit,))

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return {
        "data": rows,
        "meta": {
            "limit": limit,
            "count": len(rows)
        }
    }


@router.get("/signals/summary")
def signal_summary():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            signal_type,
            severity,
            COUNT(*) AS hits,
            SUM(score_weight) AS total_weight,
            AVG(confidence)::INT AS avg_confidence
        FROM reputation_signals
        GROUP BY signal_type, severity
        ORDER BY hits DESC;
    """)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return {"data": rows}


@router.get("/blocklist.txt", response_class=PlainTextResponse)
def get_blocklist():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT indicator
        FROM reputation_scores
        WHERE verdict = 'malicious'
           OR score >= 70
        ORDER BY score DESC
        LIMIT 10000;
    """)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    ips = [row["indicator"] for row in rows]

    return "\n".join(ips) + "\n"

@router.post("/report")
def submit_ip_report(report: IPReport):
    indicator = report.indicator.strip()
    category = report.category.strip().lower()
    confidence = max(1, min(int(report.confidence), 100))
    severity = report.severity.strip().lower()
    evidence = report.evidence or ""

    severity_weights = {
        "low": 5,
        "medium": 15,
        "high": 25,
        "critical": 40,
    }

    if severity not in severity_weights:
        severity = "medium"

    score_weight = severity_weights[severity]

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO reputation_user_reports
            (
                indicator,
                category,
                confidence,
                severity,
                evidence,
                source_url,
                reporter_name,
                reporter_email
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
        """, (
            indicator,
            category,
            confidence,
            severity,
            evidence,
            report.source_url,
            report.reporter_name,
            report.reporter_email,
        ))

        report_id = cur.fetchone()["id"]

        cur.execute("""
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
            VALUES (
                'user_report',
                'community',
                'ip_reported',
                'ip',
                %s,
                %s,
                %s,
                %s,
                %s,
                NOW()
            )
            RETURNING id;
        """, (
            indicator,
            confidence,
            severity,
            Json({
                "category": category,
                "evidence": evidence,
                "source_url": report.source_url,
                "report_id": report_id,
            }),
            Json({
                "source_table": "reputation_user_reports",
                "report_id": report_id,
            }),
        ))

        raw_event_id = cur.fetchone()["id"]

        cur.execute("""
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
            VALUES (
                'ip',
                %s,
                'user_report',
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            );
        """, (
            indicator,
            f"user_report_{category}",
            score_weight,
            confidence,
            severity,
            f"User report: {category} - {evidence}",
            raw_event_id,
        ))

        conn.commit()

    finally:
        cur.close()
        conn.close()

    result = calculate_reputation(indicator)

    return {
        "data": {
            "report_id": report_id,
            "indicator": indicator,
            "message": "IP report submitted successfully",
            "reputation": result,
        }
    }



class ExternalIntelReport(BaseModel):
    indicator: str
    provider: str
    provider_score: int = 0
    provider_verdict: Optional[str] = None
    categories: Optional[list[str]] = []
    country_code: Optional[str] = None
    usage_type: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    total_reports: int = 0
    last_reported_at: Optional[str] = None
    raw_response: Optional[dict] = {}


@router.post("/external")
def submit_external_intel(report: ExternalIntelReport):
    from reputationwatch.sync_external_intel import upsert_external_intel

    result = upsert_external_intel(
        indicator=report.indicator,
        provider=report.provider,
        provider_score=report.provider_score,
        provider_verdict=report.provider_verdict,
        categories=report.categories,
        country_code=report.country_code,
        usage_type=report.usage_type,
        isp=report.isp,
        domain=report.domain,
        total_reports=report.total_reports,
        last_reported_at=report.last_reported_at,
        raw_response=report.raw_response,
    )

    return {
        "data": {
            "message": "External intel submitted successfully",
            "indicator": report.indicator,
            "provider": report.provider,
            "reputation": result,
        }
    }


@router.get("/lookup/{indicator}")
def lookup_indicator_flow(indicator: str):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            indicator,
            score,
            verdict,
            confidence,
            sources,
            evidence,
            last_updated
        FROM reputation_scores
        WHERE indicator = %s;
    """, (indicator,))

    score_row = cur.fetchone()

    if not score_row:
        cur.close()
        conn.close()

        return {
            "data": {
                "indicator": indicator,
                "found": False,
                "status": "not_found",
                "verdict": "unknown",
                "score": 0,
                "message": "No reputation record found for this indicator.",
                "next_actions": [
                    "submit_user_report",
                    "check_external_sources",
                    "add_to_watchlist"
                ]
            }
        }

    cur.execute("""
        SELECT
            signal_type,
            severity,
            score_weight,
            confidence,
            source,
            evidence,
            raw_event_id
        FROM reputation_signals
        WHERE indicator = %s
        ORDER BY score_weight DESC, id DESC;
    """, (indicator,))

    signals = cur.fetchall()

    cur.close()
    conn.close()

    explanation = build_explanation(
        score_row["score"],
        score_row["verdict"],
        signals
    )

    return {
        "data": {
            "indicator": score_row["indicator"],
            "found": True,
            "status": "found",
            "score": score_row["score"],
            "verdict": score_row["verdict"],
            "confidence": score_row["confidence"],
            "sources": score_row["sources"],
            "last_updated": score_row["last_updated"],
            "explanation": explanation,
            "summary": {
                "total_signals": len(signals),
                "critical_signals": len([s for s in signals if s["severity"] == "critical"]),
                "high_signals": len([s for s in signals if s["severity"] == "high"]),
                "medium_signals": len([s for s in signals if s["severity"] == "medium"]),
                "low_signals": len([s for s in signals if s["severity"] == "low"]),
            },
            "signals": signals,
            "evidence": score_row["evidence"],
            "next_actions": [
                "view_full_evidence",
                "submit_additional_report",
                "export_indicator"
            ],
            "context": get_ip_context(indicator),
        }
    }
