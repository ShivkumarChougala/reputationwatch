export default function VerdictSummary({ data }) {
  if (!data) return null;

  const { indicator, score, verdict, confidence, sources, last_updated } = data;

  function getScoreClass(score) {
    if (score >= 80) return "rw-risk-high";
    if (score >= 50) return "rw-risk-medium";
    return "rw-risk-low";
  }

  return (
    <section className="rw-report-header">
      <div>
        <div className="rw-report-label">IP Reputation Report</div>
        <div className="rw-ip">{indicator}</div>

        <div className="rw-meta">
          Updated {last_updated || "-"} · Source: {sources?.join(", ") || "-"}
        </div>
      </div>

      <div className="rw-score-box">
        <div className={`rw-score-number ${getScoreClass(score)}`}>
          {score ?? "-"}
        </div>

        <div className={`rw-verdict-pill ${getScoreClass(score)}`}>
          {verdict || "unknown"} · {confidence || "low"} confidence
        </div>
      </div>
    </section>
  );
}
