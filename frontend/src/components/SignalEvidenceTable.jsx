export default function SignalEvidenceTable({ data }) {
  const signals = data?.signals || [];

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
            {signals.map((s, i) => (
              <tr key={i}>
                <td className="rw-strong">
                  {(s.signal_type || s.type || "-").replaceAll("_", " ")}
                </td>
                <td>{s.evidence || "-"}</td>
                <td>{s.source || "-"}</td>
                <td className="rw-severity">{s.severity || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
