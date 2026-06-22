import json
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent.parent

RISK_REPORT = (
    BASE_DIR
    / "module_identity_risk"
    / "reports"
    / "identity_risk_report.json"
)

REPORT_DIR = (
    BASE_DIR
    / "module_access_review"
    / "reports"
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

with open(RISK_REPORT, "r") as f:
    risk_data = json.load(f)

campaign = []

review_counter = 1

for identity in risk_data["identity_risks"]:

    if identity["risk_score"] == 0:
        continue

    review = {
        "review_id":
            f"REV-{review_counter:04}",
        "identity_id":
            identity["identity_id"],
        "name":
            identity["name"],
        "email":
            identity["email"],
        "department":
            identity["department"],
        "risk_score":
            identity["risk_score"],
        "severity":
            identity["severity"],
        "recommended_action":
            identity["recommended_action"],
        "review_status":
            "Pending",
        "reviewer":
            identity.get("manager"),
        "created_at":
            datetime.utcnow().isoformat() + "Z"
    }

    campaign.append(review)

    review_counter += 1

output = {
    "campaign_name":
        "Q2 2026 Privileged Access Review",
    "generated_at":
        datetime.utcnow().isoformat() + "Z",
    "total_reviews":
        len(campaign),
    "reviews":
        campaign
}

output_file = (
    REPORT_DIR
    / "access_review_campaign.json"
)

with open(output_file, "w") as f:
    json.dump(
        output,
        f,
        indent=2
    )

print(
    f"[+] Reviews Generated: {len(campaign)}"
)

print(
    f"[+] Report: {output_file}"
)
