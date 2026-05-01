export default function SearchHero({ ip, setIp, onLookup, loading }) {
  return (
    <section className="rw-hero">
      <div className="rw-badge">Explainable IP Reputation Intelligence</div>

      <h1>
        Investigate suspicious IPs
        <br />
        with evidence, context, and confidence.
      </h1>

      <p className="rw-subtitle">
        ReputationWatch converts honeypot activity, user reports, and external
        intelligence into clear reputation verdicts that analysts can trust.
      </p>

      <form className="rw-search" onSubmit={onLookup}>
        <input
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder="Enter IP address, example 87.121.84.136"
        />

        <button type="submit" disabled={loading}>
          {loading ? "Checking..." : "Lookup IP"}
        </button>
      </form>
    </section>
  );
}
