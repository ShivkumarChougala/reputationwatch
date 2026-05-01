export default function AnalystExplanation({ data }) {
  if (!data) return null;

  const summary = data?.summary || {};

  return (
    <div className="rw-card">
      <h3>Analyst Explanation</h3>

      <div className="rw-explanation">
        {data.explanation || "No explanation available."}
      </div>

      <div className="rw-stat-grid">
        <div className="rw-stat">
          <b>{summary.total_signals ?? 0}</b>
          <span>Total signals</span>
        </div>

        <div className="rw-stat">
          <b>{summary.critical_signals ?? 0}</b>
          <span>Critical signals</span>
        </div>

        <div className="rw-stat">
          <b>{summary.high_signals ?? 0}</b>
          <span>High signals</span>
        </div>
      </div>
    </div>
  );
}
