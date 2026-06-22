import json
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent.parent

DECISION_FILE = (
    BASE_DIR
    / "module_decision_engine"
    / "reports"
    / "review_decisions.json"
)

REPORT_DIR = (
    BASE_DIR
    / "module_evidence_vault"
    / "reports"
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

with open(DECISION_FILE, "r") as f:
    decisions = json.load(f)

evidence_records = []

for decision in decisions["decisions"]:

    evidence = {
        "evidence_id":
            f"EVD-{decision['review_id']}",

        "review_id":
            decision["review_id"],

        "identity":
            decision["identity"],

        "reviewer":
            decision["reviewer"],

        "decision":
            decision["decision"],

        "risk_score":
            decision["risk_score"],

        "severity":
            decision["severity"],

        "evidence_created":
            datetime.utcnow().isoformat() + "Z",

        "audit_status":
            "Ready"
    }

    evidence_records.append(evidence)

output = {
    "vault_name":
        "TrustShield Evidence Vault",

    "generated_at":
        datetime.utcnow().isoformat() + "Z",

    "total_evidence":
        len(evidence_records),

    "evidence":
        evidence_records
}

output_file = (
    REPORT_DIR
    / "audit_evidence.json"
)

with open(output_file, "w") as f:
    json.dump(
        output,
        f,
        indent=2
    )

print(
    f"[+] Evidence Records: {len(evidence_records)}"
)

print(
    f"[+] Report: {output_file}"
)
