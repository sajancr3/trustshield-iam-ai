import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

QUALITY_FILE = BASE_DIR / "module_identity_quality" / "reports" / "identity_quality_report.json"
RISK_FILE = BASE_DIR / "module_identity_risk" / "reports" / "identity_risk_report.json"

REPORT_DIR = BASE_DIR / "module_governance_health" / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


quality = load_json(QUALITY_FILE)
risk = load_json(RISK_FILE)

avg_quality = quality["summary"]["average_quality_score"]

critical = risk["summary"]["critical"]
high = risk["summary"]["high"]
medium = risk["summary"]["medium"]

score = avg_quality

score -= critical * 8
score -= high * 4
score -= medium * 2

score = max(0, round(score))

if score >= 90:
    status = "Excellent"
elif score >= 75:
    status = "Good"
elif score >= 60:
    status = "Needs Attention"
else:
    status = "Poor"

result = {
    "governance_health_score": score,
    "status": status,
    "average_data_quality": avg_quality,
    "critical_risks": critical,
    "high_risks": high,
    "medium_risks": medium
}

output = REPORT_DIR / "governance_health.json"

with open(output, "w") as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
