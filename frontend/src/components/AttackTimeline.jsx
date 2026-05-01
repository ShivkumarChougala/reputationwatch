export default function AttackTimeline({ data }) {
  const signals = data?.signals || [];

  const timeline = signals.slice(0, 6).map((signal) => ({
    title: signal.type || "Reputation signal",
    text: signal.evidence || signal.command || "Signal observed",
    source: signal.source || "unknown",
  }));

  return (
    <div className="rw-card">
      <h3>Attack Chain Timeline</h3>

      {timeline.length === 0 ? (
        <p className="rw-muted">No timeline events available.</p>
      ) : (
        <div className="rw-timeline">
          {timeline.map((event, index) => (
            <div className="rw-event" key={index}>
              <div className="rw-dot" />

              <div>
                <div className="rw-event-title">{event.title}</div>
                <div className="rw-event-text">
                  {event.text}
                  <br />
                  Source: {event.source}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
