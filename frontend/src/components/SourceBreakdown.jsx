export default function SourceBreakdown({ data }) {
  const sources = data?.sources || [];
  const signals = data?.signals || [];

  function countSource(source) {
    return signals.filter((s) => s.source === source).length;
  }

  return (
    <div className="rw-card">
      <h3>Source Breakdown</h3>

      {sources.length === 0 ? (
        <p className="rw-muted">No sources available.</p>
      ) : (
        sources.map((source) => (
          <div className="rw-source-row" key={source}>
            <b>{source}</b>
            <span>{countSource(source)} signals</span>
          </div>
        ))
      )}
    </div>
  );
}
