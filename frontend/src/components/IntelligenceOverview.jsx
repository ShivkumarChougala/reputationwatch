export default function IntelligenceOverview({ data }) {
  const summary = data?.summary || {};

  const items = [
    {
      label: "Signals",
      value: summary.total_signals ?? 0,
    },
    {
      label: "Critical",
      value: summary.critical ?? 0,
    },
    {
      label: "Verdict",
      value: data?.verdict || "unknown",
    },
    {
      label: "Confidence",
      value: data?.confidence || "low",
    },
  ];

  return (
    <div className="rw-overview-row">
      {items.map((item) => (
        <div className="rw-overview-item" key={item.label}>
          <span>{item.label}</span>
          <b>{item.value}</b>
        </div>
      ))}
    </div>
  );
}
