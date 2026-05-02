export default function SourceBreakdown({ data }) {
  const signals = data?.signals || [];
  const externalIntel = data?.external_intel || [];

  const rawSources = data?.sources || [];
  const sources = rawSources.filter((s) =>
    signals.some((sig) => sig.source === s)
  );

  // 🔥 FIX: only show external checks if real data exists
  const externalChecks = externalIntel.filter((intel) => {
    const hasSignal = sources.includes(intel.provider);

    const hasRealData =
      (intel.provider_score || 0) > 0 ||
      (intel.total_reports || 0) > 0 ||
      intel.latest_report;

    return !hasSignal && hasRealData;
  });

  const sourceSignals = (source) => signals.filter((s) => s.source === source);

  const truncate = (text = "", max = 130) => {
    if (!text) return "";
    return text.length > max ? text.slice(0, max).trim() + "..." : text;
  };

  const formatProvider = (p = "") =>
    p.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase());

  const getSourceMeta = (source) => ({
    label: `${sourceSignals(source).length} signals`,
    latest: sourceSignals(source).at(-1)?.evidence || "Activity observed.",
  });

  return (
    <div className="rw-card">
      <div className="rw-section-header">
        <div>
          <h3>Sources</h3>
          <p className="rw-muted">
            Risk-contributing sources and external checks.
          </p>
        </div>
      </div>

      {sources.length > 0 ? (
        <div className="rw-source-list">
          {sources.map((source) => {
            const meta = getSourceMeta(source);

            return (
              <div className="rw-source-item" key={source}>
                <div>
                  <strong>{source}</strong>
                  <span className="rw-source-meta"> · {meta.label}</span>
                  <div className="rw-source-last">
                    last: {truncate(meta.latest)}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <p className="rw-empty-text">
          No source contributed risk to this verdict.
        </p>
      )}

      {externalChecks.length > 0 && (
        <>
          <div className="rw-mini-header" style={{ marginTop: "18px" }}>
            <h4>External Checks</h4>
            <p>Providers checked without increasing risk.</p>
          </div>

          <div className="rw-source-list">
            {externalChecks.map((intel) => (
              <div className="rw-source-item" key={intel.provider}>
                <div>
                  <strong>{formatProvider(intel.provider)}</strong>
                  <span className="rw-source-meta">
                    {" "}
                    · {intel.total_reports} reports
                  </span>
                  <div className="rw-source-last">
                    {truncate(intel.latest_report)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
