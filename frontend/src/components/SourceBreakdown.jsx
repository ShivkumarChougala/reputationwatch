export default function SourceBreakdown({ data }) {
  const sources = data?.sources || [];
  const signals = data?.signals || [];
  const externalIntel = data?.external_intel || [];

  function sourceSignals(source) {
    return signals.filter((s) => s.source === source);
  }

  function shortText(text, max = 90) {
    if (!text) return "";
    return text.length > max ? text.slice(0, max) + "..." : text;
  }

  function getGhosttrapSummary() {
    const ghostSignals = sourceSignals("ghosttrap");

    const lastSignal = ghostSignals[0];
    const riskTypes = ghostSignals
      .map((s) => s.signal_type?.replaceAll("_", " "))
      .filter(Boolean)
      .slice(0, 2)
      .join(" + ");

    return {
      count: ghostSignals.length,
      last: lastSignal?.evidence || "",
      risk: riskTypes || "behavior observed",
    };
  }

  return (
    <div className="rw-card">
      <h3>Sources</h3>

      {sources.length === 0 ? (
        <p className="rw-muted">No sources available.</p>
      ) : (
        sources.map((source) => {
          const intel = externalIntel.find((i) => i.provider === source);
          const sourceCount = sourceSignals(source).length;
          const ghost = source === "ghosttrap" ? getGhosttrapSummary() : null;

          return (
            <div className="rw-source-row" key={source}>
              <div>
                <b>{source}</b>

                {intel && (
                  <>
                    <span className="rw-muted">
                      {" "}· {intel.total_reports} reports
                    </span>
                    {intel.latest_report && (
                      <div className="rw-source-detail">
                        last: {shortText(intel.latest_report)}
                      </div>
                    )}
                  </>
                )}

                {ghost && (
                  <>
                    <span className="rw-muted">
                      {" "}· {ghost.count} behaviors
                    </span>
                    <div className="rw-source-detail">
                      risk: {ghost.risk}
                    </div>
                    {ghost.last && (
                      <div className="rw-source-detail">
                        last: {shortText(ghost.last)}
                      </div>
                    )}
                  </>
                )}
              </div>

              <span className="rw-muted">{sourceCount} signals</span>
            </div>
          );
        })
      )}
    </div>
  );
}
