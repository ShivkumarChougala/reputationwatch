export default function AttackTimeline({ data }) {
  const signals = data?.signals || [];
  const externalIntel = data?.external_intel || [];

  function getExternalLatest(source) {
    const intel = externalIntel.find((i) => i.provider === source);
    return intel?.latest_report || "";
  }

  function cleanEvidence(evidence, source) {
    if (!evidence) return "";

    if (source === "abuseipdb") {
      const match = evidence.match(/latest_report='([^']+)'/);
      let text = match?.[1] || getExternalLatest(source) || "";

      if (!text) return "No abuse reports found";

      text = text.replace(/^\d{4}-\d{2}-\d{2}T.*?\s/, "");
      text = text.split("\n")[0];

      if (text.length > 120) {
        text = text.slice(0, 120) + "...";
      }

      return text;
    }

    return evidence
      .replace("Payload download command observed:", "Download:")
      .replace("Permission change command observed:", "Permission:")
      .replace("Script or binary execution attempt observed:", "Execute:")
      .replace("Destructive command observed:", "Cleanup:")
      .replace("Environment discovery command observed:", "Discovery:")
      .trim();
  }

  function phaseFor(signal) {
    const type = (signal.signal_type || "").toLowerCase();

    if (type.includes("external")) {
      return { key: "initial", title: "Initial Intel", label: "External reputation" };
    }

    if (type.includes("environment") || type.includes("recon")) {
      return { key: "recon", title: "Reconnaissance", label: "Host discovery" };
    }

    if (type.includes("payload")) {
      return { key: "download", title: "Payload Download", label: "File retrieval" };
    }

    if (type.includes("permission")) {
      return { key: "permission", title: "Permission Change", label: "Prepare execution" };
    }

    if (type.includes("execution")) {
      return { key: "execution", title: "Execution", label: "Script / binary run" };
    }

    if (type.includes("persistence")) {
      return { key: "persistence", title: "Persistence", label: "Access retention" };
    }

    if (type.includes("destructive")) {
      return { key: "impact", title: "Cleanup / Impact", label: "Destructive action" };
    }

    return { key: "other", title: "Other Activity", label: "Observed signal" };
  }

  const order = [
    "initial",
    "recon",
    "download",
    "permission",
    "execution",
    "persistence",
    "impact",
    "other",
  ];

  const grouped = new Map();

  signals.forEach((signal) => {
    const phase = phaseFor(signal);
    const evidence = cleanEvidence(signal.evidence, signal.source);

    if (!grouped.has(phase.key)) {
      grouped.set(phase.key, {
        ...phase,
        items: [],
        sources: new Set(),
        severities: new Set(),
      });
    }

    const group = grouped.get(phase.key);

    if (evidence && !group.items.includes(evidence)) {
      group.items.push(evidence);
    }

    if (signal.source) group.sources.add(signal.source);
    if (signal.severity) group.severities.add(signal.severity);
  });

  const phases = order.map((key) => grouped.get(key)).filter(Boolean);

  function severityLabel(severities) {
    if (severities.has("critical")) return "critical";
    if (severities.has("high")) return "high";
    if (severities.has("medium")) return "medium";
    return "low";
  }

  return (
    <div className="rw-card">
      <h3>Attack Chain Timeline</h3>

      {phases.length === 0 ? (
        <p className="rw-muted">No activity available.</p>
      ) : (
        <div className="rw-chain">
          {phases.map((phase, index) => (
            <div className="rw-chain-step" key={phase.key}>
              <div className="rw-chain-marker">
                <span>{index + 1}</span>
              </div>

              <div className="rw-chain-content">
                <div className="rw-chain-head">
                  <div>
                    <h4>{phase.title}</h4>
                    <p>{phase.label}</p>
                  </div>

                  <span className={`rw-chain-severity rw-chain-${severityLabel(phase.severities)}`}>
                    {severityLabel(phase.severities)}
                  </span>
                </div>

                <div className="rw-chain-body">
                  {phase.items.slice(0, 3).map((item, i) => (
                    <div className="rw-chain-evidence" key={i}>
                      {item}
                    </div>
                  ))}

                  {phase.items.length > 3 && (
                    <div className="rw-muted">
                      +{phase.items.length - 3} more observations
                    </div>
                  )}
                </div>

                <div className="rw-chain-source">
                  Source: {Array.from(phase.sources).join(", ")}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
