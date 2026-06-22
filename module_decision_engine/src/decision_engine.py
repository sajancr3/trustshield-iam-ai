import json
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent.parent

CAMPAIGN_FILE = (
    BASE_DIR
    / "module_access_review"
    / "reports"
    / "access_review_campaign.json"
)

REPORT_DIR = (
    BASE_DIR
    / "module_decision_engine"
    / "reports"
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

with open(CAMPAIGN_FILE, "r") as f:
    campaign = json.load(f)

decisions = []

for review in campaign["reviews"]:

    if review["severity"] == "Critical":
        decision = "REMOVE"

    elif review["severity"] == "High":
        decision = "REMOVE"

    elif review["severity"] == "Medium":
        decision = "ESCALATE"

    else:
        decision = "APPROVE"

    decisions.append({
        "review_id": review["review_id"],
        "identity": review["email"],
        "risk_score": review["risk_score"],
        "severity": review["severity"],
        "reviewer": review["reviewer"],
        "decision": decision,
        "decision_time":
            datetime.utcnow().isoformat() + "Z"
    })

output = {
    "generated_at":
        datetime.utcnow().isoformat() + "Z",
    "total_decisions":
        len(decisions),
    "decisions":
        decisions
}

output_file = (
    REPORT_DIR
    / "review_decisions.json"
)

with open(output_file, "w") as f:
    json.dump(
        output,
        f,
        indent=2
    )

print(
    f"[+] Decisions Generated: {len(decisions)}"
)

print(
    f"[+] Report: {output_file}"
)
