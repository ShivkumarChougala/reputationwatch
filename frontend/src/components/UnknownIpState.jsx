export default function UnknownIpState({ ip }) {
  return (
    <div className="rw-empty">
      <h3>No intelligence found</h3>

      <p className="rw-muted">
        No reputation data is currently available for <b>{ip}</b>.
        You can submit a report or enrich this IP using external sources.
      </p>

      <div style={{ marginTop: "20px", display: "flex", gap: "10px", flexWrap: "wrap" }}>
        <button className="rw-button-outline">Submit Report</button>
        <button className="rw-button-outline">Check External Sources</button>
        <button className="rw-button-outline">Add to Watchlist</button>
      </div>
    </div>
  );
}
