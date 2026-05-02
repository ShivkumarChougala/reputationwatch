# ReputationWatch

> Explainable IP Reputation Intelligence powered by real attacker telemetry.

ReputationWatch is an enterprise-grade IP reputation platform that analyzes attacker behavior, external intelligence, and user reports to produce transparent, evidence-backed security verdicts.

Built on top of the GhostTrap honeypot network, it transforms raw attack data into actionable threat intelligence.

---

## 🚀 Overview

ReputationWatch aggregates and analyzes multiple intelligence sources:

* First-party attacker telemetry (GhostTrap honeypots)
* External threat intelligence (AbuseIPDB, VirusTotal, etc.)
* Community/user reports
* Behavioral signal analysis (commands, payloads, persistence attempts)

It produces:

* Reputation Score (0–100)
* Verdict (safe / suspicious / malicious)
* Confidence Level
* Explainable Evidence (why the verdict was assigned)

---

## 🔍 Key Features

### IP Reputation Lookup

* Real-time IP analysis
* Multi-source intelligence aggregation
* Context enrichment (ASN, ISP, geo, timezone)

### Explainable Scoring Engine

* Signal-based scoring (not black-box)
* Weighted threat categories:

  * Reconnaissance
  * Payload download
  * Execution attempts
  * Persistence techniques
  * Destructive behavior
* Transparent reasoning output

### Threat Intelligence Pipeline

* Syncs attacker commands → converts to signals
* Ingests external intelligence providers
* Merges signals into a unified model

### Evidence & Timeline

* Attack timeline visualization
* Signal breakdown by severity
* Source attribution (GhostTrap, external, user)

### Community Reporting

* Users can submit abuse reports
* Reports directly influence reputation scoring

### Blocklist Generation

* Export high-risk IPs
* Ready-to-use blocklist endpoint

---

## 🧠 How It Works

```
GhostTrap Sensors
        │
        ▼
Raw Attack Telemetry
        │
        ▼
Signal Classification Engine
        │
        ├── External Intelligence APIs
        │
        ▼
Reputation Engine
        │
        ▼
Score + Verdict + Explanation
        │
        ▼
API + Dashboard
```

---

## ⚙️ Tech Stack

### Backend

* Python (FastAPI)
* PostgreSQL
* Psycopg2

### Frontend

* React (Vite)
* Recharts

### Intelligence Sources

* GhostTrap (first-party)
* AbuseIPDB
* VirusTotal (planned)
* GreyNoise (planned)

---

## 📡 API Example

### Lookup IP

GET /api/v1/reputation/lookup/{ip}

### Response

```json
{
  "indicator": "87.121.84.136",
  "score": 100,
  "verdict": "malicious",
  "confidence": "high",
  "sources": ["ghosttrap"],
  "explanation": "Strong attacker behavior including payload execution and destructive commands.",
  "summary": {
    "total_signals": 8,
    "critical_signals": 3,
    "high_signals": 2
  }
}
```

---

## 🧩 Signal Types

* system_reconnaissance
* payload_download
* execution_attempt
* sensitive_file_access
* persistence_attempt
* destructive_command
* ssh_bruteforce
* external_abuse_report

Each signal contributes to the final score with capped weights.

---

## 🔐 Why ReputationWatch?

Most reputation systems are black boxes.

ReputationWatch is different:

* Explainable decisions
* Real attacker behavior (not just passive data)
* Multi-source intelligence
* Designed for SOC / security teams

---

## 🌐 Live Demo

https://reputation.thechougala.in/

---

## 🌐 Use Cases

* Firewall / WAF blocking decisions
* SOC investigation workflows
* Threat intelligence enrichment
* Security dashboards
* API-based integrations

---

## 🛠️ Installation (Dev)

```bash
git clone https://github.com/yourusername/reputationwatch.git
cd reputationwatch

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

uvicorn api.main:app --reload
```

---

## 🔄 Workers

```bash
python3 -m reputationwatch.sync_commands
python3 -m reputationwatch.sync_external_intel
```

---

## 📊 Roadmap

* Machine learning-based scoring
* Botnet classification
* Real-time streaming signals
* Multi-tenant SaaS dashboard
* API key management & billing
* Global sensor deployment system

---

## 🧪 Project Status

Active development — building towards a full enterprise threat intelligence platform.

---

## 🤝 Contributing

Contributions are welcome. Please open issues or submit pull requests.

---

## 📜 License

MIT License

---

## 🔥 Vision

ReputationWatch aims to become:

The most transparent and behavior-driven IP reputation system on the internet.
