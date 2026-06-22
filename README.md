# TrustShield IAM AI

**AI-powered Identity Governance and Administration (IGA) platform** with risk intelligence, LLM-assisted advisory, tamper-evident audit evidence, and a real-time Streamlit dashboard.

Built as a controlled enterprise simulation demonstrating production IAM/IGA workflows: identity ingestion, risk scoring, access review, AI-guided remediation, and cryptographic audit sealing.

---

## What It Does

TrustShield ingests identity data from HR, Active Directory, and group membership sources, runs a full governance pipeline, and surfaces identity risks through an interactive CLI and Streamlit dashboard. An embedded Ollama LLM (AI Governance Advisor) provides natural-language remediation guidance based on live risk findings.

### Core Pipeline
HR Export CSV

AD Export CSV      →  Identity Fabric  →  Quality Engine  →  Risk Engine

Groups CSV
Risk Engine  →  Access Review  →  Decision Engine  →  Evidence Vault

→  Quantum Integrity Seal

→  SQLite Data Store

→  Streamlit Dashboard
---

## Modules

| Module | Purpose |
|---|---|
| `module_identity_fabric` | Normalises and merges HR + AD + group data into unified identity records |
| `module_identity_quality` | Detects data quality issues: missing managers, malformed emails, incomplete profiles |
| `module_identity_risk` | Scores each identity across MFA, dormancy, group privilege, and termination status |
| `module_access_review` | Runs periodic access certifications, flags stale entitlements |
| `module_decision_engine` | Makes access allow/flag/revoke decisions based on risk thresholds |
| `module_evidence_vault` | Stores timestamped audit evidence for every governance action |
| `module_quantum_integrity` | Seals evidence with SHA3-512 + HMAC-SHA3-512 + Ed25519 signatures |
| `module_ai_governance` | Governance health scoring and executive KPI reporting |
| `module_ollama_copilot` | LLM-powered advisory — natural language remediation guidance via Ollama |
| `module_data_store` | SQLite persistence layer shared across all modules |
| `app/` | Streamlit real-time dashboard |

---

## Key Features

**Identity Risk Intelligence**
- MFA enforcement gap detection
- Dormant account identification (90+ days inactive)
- Terminated user access risk flagging
- Orphan account and missing manager detection
- High-risk department heatmap
- Per-identity risk scoring: Critical / High / Medium / Low

**Remediation Workflows**
- Enable MFA
- Assign manager
- Disable / offboard account
- Remove privileged group access
- Trigger governance review
- Generate audit evidence
- All remediations re-run the full pipeline to recalculate scores

**AI Governance Advisor (Ollama)**
- Local LLM (llama3 / mistral / phi3) provides remediation recommendations
- Runs fully on-premises — no identity data leaves the environment
- Interprets live identity risk context and advises on priority actions

**Quantum Integrity Vault**
- Every governance event sealed with SHA3-512 (NIST post-quantum safe hash)
- HMAC-SHA3-512 for keyed authenticity verification
- Ed25519 digital signatures for non-repudiation
- Tamper detection on any stored audit receipt

**Streamlit Dashboard**
- Real-time identity risk overview
- Drill-down by department, severity, and identity
- Governance health KPIs

---

## Tech Stack

- Python 3.12
- Streamlit
- SQLite
- Ollama (local LLM)
- cryptography (Ed25519, HMAC-SHA3)
- Pandas
- Docker + Docker Compose

---

## Quick Start

### Option 1 — Docker (recommended)

```bash
git clone https://github.com/sajancr3/trustshield-iam-ai.git
cd trustshield-iam-ai

cp .env.example .env

docker compose up -d

docker exec trustshield_ollama ollama pull llama3

open http://localhost:8501
```

### Option 2 — CLI

```bash
docker compose --profile cli run trustshield-cli
```

### Option 3 — Local

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 start.py
```

---

## Data Input Format

**module_identity_fabric/raw/hr_export.csv**
employee_id,full_name,email,department,manager,status

EMP001,Jane Smith,jane@company.com,Finance,manager@company.com,Active
**module_identity_fabric/raw/ad_export.csv**
email,group_name

jane@company.com,Domain-Admins
---

## Architecture
Attacker VM (Ubuntu)

|

v

SOC VM (Debian) — Suricata IDS

|

v

TrustShield IAM AI

Identity Fabric → Quality → Risk Engine

Access Review → Decision Engine

Evidence Vault → Quantum Integrity Seal

AI Governance Advisor (Ollama LLM)

SQLite DB  |  Streamlit Dashboard
---

## Security Design

- All LLM inference runs locally via Ollama — no identity data sent externally
- HMAC keys and signing keys stored with chmod 600, never committed to git
- trustshield.db excluded from version control
- SHA3-512 chosen as quantum-resistant hash (resistant to Grover's algorithm speedup)
- Ed25519 signatures for non-repudiable audit receipts

---

## Author

Sajan Chakkumkattuparambil Raju — Cybersecurity Engineer, Warsaw, Poland

[linkedin.com/in/sajanchakkumkattuparambilraju](https://linkedin.com/in/sajanchakkumkattuparambilraju) | [sajan-cyber-portfolio.vercel.app](https://sajan-cyber-portfolio.vercel.app)
