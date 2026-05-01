export default function ApiAccessCard({ ip }) {
  const endpoint = `GET /api/v1/reputation/lookup/${ip}`;

  function copy() {
    navigator.clipboard.writeText(endpoint);
    alert("API endpoint copied");
  }

  return (
    <div className="rw-card">
      <h3>API Access</h3>

      <p className="rw-muted">
        Use this endpoint in your SIEM, firewall, or automation pipeline.
      </p>

      <div
        style={{
          background: "#f3f4f6",
          padding: "14px",
          borderRadius: "12px",
          fontSize: "13px",
          marginTop: "12px",
        }}
      >
        {endpoint}
      </div>

      <button
        onClick={copy}
        style={{ marginTop: "12px" }}
        className="rw-button-outline"
      >
        Copy Endpoint
      </button>
    </div>
  );
}
