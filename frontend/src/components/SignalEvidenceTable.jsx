export default function SignalEvidenceTable({ data }) {
  const signals = data?.signals || [];
  const externalIntel = data?.external_intel || [];

  function getExternalLatest(source) {
    const intel = externalIntel.find((i) => i.provider === source);
    return intel?.latest_report || "";
  }

  function cleanEvidence(evidence, source) {
    if (!evidence) return "-";

    if (source === "abuseipdb") {
      // Try extracting latest_report
      const match = evidence.match(/latest_report='([^']+)'/);
      let text = match?.[1] || getExternalLatest(source) || "";

      if (!text) return "No abuse reports found";

      // Remove ISO timestamp at start
      text = text.replace(/^\d{4}-\d{2}-\d{2}T.*?\s/, "");

      // Keep only first line
      text = text.split("\n")[0];

      // Shorten long logs
      if (text.length > 120) {
        text = text.slice(0, 120) + "...";
      }

      return text;
    }

    return evidence;
  }

  function formatType(type = "") {
    return type
      .replaceAll("_", " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
  }

  function typeClass(type = "") {
    const t = type.toLowerCase();

    if (t.includes("destructive")) return "rw-signal-critical";
    if (t.includes("persistence")) return "rw-signal-purple";
    if (t.includes("execution")) return "rw-signal-high";
    if (t.includes("payload")) return "rw-signal-high";
    if (t.includes("sensitive")) return "rw-signal-high";
    if (t.includes("external")) return "rw-signal-external";

    return "rw-signal-neutral";
  }

  return (
    <div className="rw-card">
      <h3>Signal Evidence</h3>

      {signals.length === 0 ? (
        <p className="rw-muted">No signals available.</p>
      ) : (
        <table className="rw-table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Evidence</th>
              <th>Source</th>
              <th>Severity</th>
            </tr>
          </thead>

          <tbody>
            {signals.map((s, i) => {
              const signalType = s.signal_type || s.type || "-";

              return (
                <tr key={i}>
                  <td className="rw-strong">
                    {formatType(signalType)}
                  </td>
                  <td>{cleanEvidence(s.evidence, s.source)}</td>
                  <td>{s.source || "-"}</td>
                  <td>
                    <span className={`rw-severity-pill ${typeClass(signalType)}`}>
                      {s.severity || "-"}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
