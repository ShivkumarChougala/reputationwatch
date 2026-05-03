# ReputationWatch

> Your reputation is only as good as your last IP address.

ReputationWatch is an IP reputation system that analyzes attacker behavior, external intelligence, and user reports to produce evidence-based security assessments.

It is built on top of the GhostTrap honeypot network.

---

## Overview

ReputationWatch processes data from:

* GhostTrap honeypot telemetry
* External intelligence providers
* User-submitted reports

The system converts this data into signals and evaluates them to produce:

* A reputation score (0–100)
* A classification (safe, low risk, suspicious, malicious)
* A confidence level
* An explanation of contributing factors

---

## Features

* IP reputation lookup with supporting evidence
* Signal-based scoring model
* Integration with external intelligence sources
* User report ingestion
* Blocklist generation

---

## How it works

```
GhostTrap Sensors → Telemetry → Signal Processing → Scoring → API
```

---

## API

### Lookup

GET /api/v1/reputation/lookup/{ip}

### Example (curl)

```bash
curl -s "https://api.thechougala.in/api/v1/reputation/lookup/87.121.84.136"
```

### Response (trimmed)

```json
{
  "indicator": "87.121.84.136",
  "score": 100,
  "verdict": "malicious",
  "confidence": "high",
  "sources": ["abuseipdb", "ghosttrap", "user_report"],
  "summary": {
    "total_signals": 14,
    "critical_signals": 2,
    "high_signals": 10
  }
}
```

---

## Getting Started

```bash
git clone https://github.com/ShivkumarChougala/reputationwatch.git
cd reputationwatch

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

uvicorn api.main:app --reload
```

---

## Background Jobs

```bash
python3 -m reputationwatch.sync_commands
python3 -m reputationwatch.sync_external_intel
```

---

## License

MIT License
