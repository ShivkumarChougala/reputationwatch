import { useState } from "react";
import { submitReport } from "../services/api";

export default function SubmitReportForm({ ip }) {
  const [type, setType] = useState("ssh_bruteforce");
  const [description, setDescription] = useState("");
  const [reporter, setReporter] = useState("");
  const [status, setStatus] = useState("idle");

  async function handleSubmit(e) {
    e.preventDefault();

    try {
      setStatus("loading");

      await submitReport({
        indicator: ip,
        report_type: type,
        description,
        reporter_email: reporter || null,
      });

      setDescription("");
      setReporter("");
      setStatus("success");
    } catch {
      setStatus("error");
    }
  }

  return (
    <div className="rw-card">
      <h3>Submit Additional Report</h3>

      <form className="rw-form" onSubmit={handleSubmit}>
        <select value={type} onChange={(e) => setType(e.target.value)}>
          <option value="ssh_bruteforce">SSH brute force</option>
          <option value="scanner">Scanner</option>
          <option value="malware_hosting">Malware hosting</option>
          <option value="abuse_source">Abuse source</option>
        </select>

        <textarea
          rows="5"
          placeholder="Describe what you observed..."
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          required
        />

        <input
          placeholder="Your email optional"
          value={reporter}
          onChange={(e) => setReporter(e.target.value)}
        />

        <button type="submit" disabled={status === "loading"}>
          {status === "loading" ? "Submitting..." : "Submit Report"}
        </button>
      </form>

      {status === "success" && (
        <p className="rw-success">Report submitted successfully.</p>
      )}

      {status === "error" && (
        <p className="rw-error">Report submission failed.</p>
      )}
    </div>
  );
}
