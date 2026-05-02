export default function CommunityIntelligence({ data }) {
  const payload = data?.data || data;
  const signals = payload?.signals || [];

  const userSignals = signals.filter((s) => s.source === "user_report");

  return (
    <div className="rw-card">
      <div className="rw-section-header">
        <div>
          <h3>Community Intelligence</h3>
          <p className="rw-muted">Human-submitted intelligence for this IP.</p>
        </div>

        <span className="rw-badge">
          {userSignals.length} {userSignals.length === 1 ? "Report" : "Reports"}
        </span>
      </div>

      {userSignals.length > 0 ? (
        <div className="rw-community-box">
          {userSignals.map((r, i) => (
            <div className="rw-community-item" key={i}>
              <div className="rw-community-row">
                <span>{String(r.signal_type || "user_report").replaceAll("_", " ")}</span>
                <b className="rw-community-severity">
                  {String(r.severity || "medium").toUpperCase()}
                </b>
              </div>

              <div className="rw-community-evidence">
                {r.evidence || "Community report submitted for this indicator."}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <p className="rw-empty-text">No community reports submitted yet.</p>
      )}
    </div>
  );
}
