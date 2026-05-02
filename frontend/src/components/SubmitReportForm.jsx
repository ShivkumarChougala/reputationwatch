import { useState } from "react";

export default function SubmitReportForm({ ip, onSubmitted }) {
  const [reportType, setReportType] = useState("ssh_bruteforce");
  const [description, setDescription] = useState("");
  const [confidence, setConfidence] = useState("high");

  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState("");
  const [statusType, setStatusType] = useState("");

  const handleSubmit = async () => {
    if (!description.trim()) {
      setStatus("Please describe what you observed.");
      setStatusType("error");
      return;
    }

    try {
      setLoading(true);
      setStatus("");
      setStatusType("");

      const res = await fetch("https://api.thechougala.in/api/v1/reputation/reports", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          indicator: ip,
          report_type: reportType,
          description,
          confidence,
        }),
      });

      if (!res.ok) throw new Error();

      setStatus("Intelligence submitted successfully.");
      setStatusType("success");
      setDescription("");

      if (onSubmitted) onSubmitted();

    } catch {
      setStatus("Submission failed. Try again.");
      setStatusType("error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="rw-card">
      <div className="rw-mini-header">
        <h4>Submit Intelligence</h4>
        <p>Report observed activity for <b>{ip}</b></p>
      </div>

      <select
        value={reportType}
        onChange={(e) => setReportType(e.target.value)}
        className="rw-input"
      >
        <option value="ssh_bruteforce">SSH Brute Force</option>
        <option value="malware">Malware Download</option>
        <option value="execution">Command Execution</option>
        <option value="recon">Recon Activity</option>
      </select>

      <textarea
        placeholder="Describe what you observed..."
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        className="rw-input"
        style={{ marginTop: "10px" }}
      />

      <select
        value={confidence}
        onChange={(e) => setConfidence(e.target.value)}
        className="rw-input"
        style={{ marginTop: "10px" }}
      >
        <option value="low">Low Confidence</option>
        <option value="medium">Medium Confidence</option>
        <option value="high">High Confidence</option>
      </select>

      <button
        onClick={handleSubmit}
        className="rw-button-primary"
        style={{ marginTop: "12px", width: "100%" }}
        disabled={loading}
      >
        {loading ? "Submitting..." : "Submit Intelligence"}
      </button>

      {status && (
        <div className={`rw-submit-status rw-submit-${statusType}`}>
          {status}
        </div>
      )}

    </div>
  );
}
