import { useState } from "react";
import Header from "./components/Header";
import SearchHero from "./components/SearchHero";
import VerdictSummary from "./components/VerdictSummary";
import IntelligenceOverview from "./components/IntelligenceOverview";
import AnalystExplanation from "./components/AnalystExplanation";
import SignalEvidenceTable from "./components/SignalEvidenceTable";
import AttackTimeline from "./components/AttackTimeline";
import IpContextPanel from "./components/IpContextPanel";
import SourceBreakdown from "./components/SourceBreakdown";
import SubmitReportForm from "./components/SubmitReportForm";
import CommunityIntelligence from "./components/CommunityIntelligence";
import UnknownIpState from "./components/UnknownIpState";
import ApiAccessCard from "./components/ApiAccessCard";
import { lookupIp } from "./services/api";
import "./styles/reputationWatch.css";

export default function App() {
  const [ip, setIp] = useState("87.121.84.136");
  const [result, setResult] = useState(null);
  const [status, setStatus] = useState("idle");
  const [error, setError] = useState("");

  async function handleLookup(e) {
    e.preventDefault();

    const cleanIp = ip.trim();

    if (!cleanIp) {
      setError("Please enter an IP address.");
      setStatus("error");
      return;
    }

    try {
      setStatus("loading");
      setError("");
      setResult(null);

      const response = await lookupIp(cleanIp);
      setResult(response?.data || response);

      setStatus("success");
    } catch (err) {
      setError(err.message || "Lookup failed.");
      setStatus("error");
    }
  }

  return (
    <>
      <Header />

      <SearchHero
        ip={ip}
        setIp={setIp}
        onLookup={handleLookup}
        loading={status === "loading"}
      />

      <main className="rw-container">
        {status === "idle" && (
          <div className="rw-status">
            Search an IP address to generate a ReputationWatch intelligence report.
          </div>
        )}

        {status === "loading" && (
          <div className="rw-status rw-loading">
            <p>Checking internal intelligence...</p>
            <p>Correlating attack signals...</p>
            <p>Enriching from external threat intel...</p>
            <p>Generating reputation verdict...</p>
          </div>
        )}

        {status === "error" && (
          <div className="rw-empty">
            <h3>Lookup failed</h3>
            <p className="rw-muted">{error}</p>
          </div>
        )}

        {status === "success" && (
          <>
            {!result?.found ? (
              <UnknownIpState ip={ip} />
            ) : (
              <>
                <VerdictSummary data={result} />
                <IntelligenceOverview data={result} />

                <div className="rw-grid">
                  <div>
                    <AnalystExplanation data={result} />
                    <SignalEvidenceTable data={result} />
                    <AttackTimeline data={result} />
                  </div>

                  <div>
                    <IpContextPanel data={result} />
                    <SourceBreakdown data={result} />
                    <CommunityIntelligence data={result} />
                    <SubmitReportForm ip={result?.indicator} />
                    <ApiAccessCard ip={result?.indicator} />
                  </div>
                </div>
              </>
            )}
          </>
        )}
      </main>
    </>
  );
}
