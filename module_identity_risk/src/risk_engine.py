import json
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent.parent

FABRIC_FILE = BASE_DIR / "module_identity_fabric" / "normalized" / "identity_fabric.json"
QUALITY_FILE = BASE_DIR / "module_identity_quality" / "reports" / "identity_quality_report.json"
REPORT_DIR = BASE_DIR / "module_identity_risk" / "reports"

REPORT_DIR.mkdir(parents=True, exist_ok=True)


def load_json(path):
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def is_empty(value):
    return value is None or str(value).strip() == "" or str(value).lower() == "nan"


def normalize_bool(value):
    return str(value).strip().lower() in ["true", "yes", "1", "enabled", "active"]


def severity_from_score(score):
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def add_signal(signals, name, weight, category, explanation, evidence):
    signals.append({
        "signal": name,
        "weight": weight,
        "category": category,
        "explanation": explanation,
        "evidence": evidence
    })


def get_quality_map():
    if not QUALITY_FILE.exists():
        return {}

    quality_data = load_json(QUALITY_FILE)
    quality_map = {}

    for item in quality_data.get("identity_quality", []):
        quality_map[str(item.get("email"))] = item

    return quality_map


def analyze_identity(identity, quality_map):
    signals = []

    email = identity.get("email")
    status = str(identity.get("status", "")).lower()
    manager = identity.get("manager")
    mfa_enabled = normalize_bool(identity.get("mfa_enabled"))
    groups = identity.get("groups", [])

    try:
        last_login_days = int(identity.get("last_login_days"))
    except (TypeError, ValueError):
        last_login_days = None

    privileged_keywords = ["admin", "privileged", "database", "domain", "payment"]
    critical_keywords = ["domain admins", "database admins", "global admins"]

    privileged_groups = [
        group for group in groups
        if any(keyword in str(group).lower() for keyword in privileged_keywords)
    ]

    critical_groups = [
        group for group in groups
        if any(keyword in str(group).lower() for keyword in critical_keywords)
    ]

    if status == "terminated" and groups:
        add_signal(
            signals,
            "Terminated identity still has access",
            40,
            "Lifecycle Risk",
            "HR status shows terminated, but the identity still has group memberships.",
            {
                "status": status,
                "groups": groups
            }
        )

    if privileged_groups and not mfa_enabled:
        add_signal(
            signals,
            "Privileged access without MFA",
            30,
            "Authentication Risk",
            "Identity has privileged access but MFA is not enabled.",
            {
                "mfa_enabled": mfa_enabled,
                "privileged_groups": privileged_groups
            }
        )

    if last_login_days is not None and last_login_days > 90 and privileged_groups:
        add_signal(
            signals,
            "Dormant privileged identity",
            35,
            "Dormant Access Risk",
            f"Identity has not logged in for {last_login_days} days but still has privileged access.",
            {
                "last_login_days": last_login_days,
                "privileged_groups": privileged_groups
            }
        )

    if len(critical_groups) > 1:
        add_signal(
            signals,
            "Excessive critical privilege concentration",
            25,
            "Least Privilege Risk",
            "Identity belongs to multiple critical privileged groups.",
            {
                "critical_groups": critical_groups
            }
        )

    if privileged_groups and is_empty(manager):
        add_signal(
            signals,
            "Privileged identity without accountable owner",
            25,
            "Ownership Risk",
            "Privileged identity has no manager or accountable business owner.",
            {
                "manager": manager,
                "privileged_groups": privileged_groups
            }
        )

    if last_login_days is not None and last_login_days > 180 and groups:
        add_signal(
            signals,
            "Stale access still assigned",
            20,
            "Access Hygiene Risk",
            f"Identity has not logged in for {last_login_days} days but still has assigned access.",
            {
                "last_login_days": last_login_days,
                "groups": groups
            }
        )

    quality = quality_map.get(str(email))

    if quality:
        quality_score = quality.get("data_quality_score", 100)

        if quality_score < 70:
            add_signal(
                signals,
                "Low identity data confidence",
                15,
                "Data Quality Risk",
                "Identity has low data quality confidence, which can weaken access review and audit decisions.",
                {
                    "data_quality_score": quality_score,
                    "confidence": quality.get("confidence"),
                    "issue_count": quality.get("issue_count")
                }
            )

    raw_score = sum(signal["weight"] for signal in signals)
    risk_score = min(raw_score, 100)

    return {
        "identity_id": identity.get("identity_id"),
        "name": identity.get("name"),
        "email": email,
        "department": identity.get("department"),
        "manager": manager,
        "status": identity.get("status"),
        "groups": groups,
        "risk_score": risk_score,
        "severity": severity_from_score(risk_score),
        "signal_count": len(signals),
        "signals": signals,
        "recommended_action": recommend_action(risk_score, signals)
    }


def recommend_action(score, signals):
    signal_names = [signal["signal"] for signal in signals]

    if score >= 90:
        return "Immediate remediation required. Disable or restrict access, validate ownership, enforce MFA, and create audit evidence."
    if "Terminated identity still has access" in signal_names:
        return "Remove access immediately and validate leaver control completion."
    if "Privileged access without MFA" in signal_names:
        return "Enable MFA and review privileged group membership."
    if score >= 70:
        return "Prioritize for access review and remediate excessive or stale access."
    if score >= 40:
        return "Review during the next access certification campaign."
    return "No urgent action required. Continue monitoring."


def generate_markdown_report(result):
    report_path = REPORT_DIR / "identity_risk_report.md"

    lines = []
    lines.append("# TrustShield IAM AI - Identity Risk Report")
    lines.append("")
    lines.append(f"Generated: {result['generated_at']}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Total Identities Reviewed: {result['summary']['total_identities']}")
    lines.append(f"- Risky Identities: {result['summary']['risky_identities']}")
    lines.append(f"- Critical: {result['summary']['critical']}")
    lines.append(f"- High: {result['summary']['high']}")
    lines.append(f"- Medium: {result['summary']['medium']}")
    lines.append(f"- Low: {result['summary']['low']}")
    lines.append("")
    lines.append("## Risk Findings")
    lines.append("")

    for identity in result["identity_risks"]:
        if identity["risk_score"] == 0:
            continue

        lines.append(f"### {identity['email']}")
        lines.append(f"- Name: {identity['name']}")
        lines.append(f"- Identity ID: {identity['identity_id']}")
        lines.append(f"- Severity: {identity['severity']}")
        lines.append(f"- Risk Score: {identity['risk_score']}")
        lines.append(f"- Department: {identity['department']}")
        lines.append(f"- Manager: {identity['manager']}")
        lines.append(f"- Recommended Action: {identity['recommended_action']}")
        lines.append("")
        lines.append("#### Risk Signals")
        lines.append("")

        for signal in identity["signals"]:
            lines.append(f"- **{signal['signal']}** ({signal['category']}, +{signal['weight']})")
            lines.append(f"  - Explanation: {signal['explanation']}")
            lines.append(f"  - Evidence: `{json.dumps(signal['evidence'])}`")

        lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def run_risk_engine():
    fabric = load_json(FABRIC_FILE)
    identities = fabric.get("identities", [])

    quality_map = get_quality_map()

    identity_risks = [
        analyze_identity(identity, quality_map)
        for identity in identities
    ]

    identity_risks = sorted(
        identity_risks,
        key=lambda item: item["risk_score"],
        reverse=True
    )

    summary = {
        "total_identities": len(identity_risks),
        "risky_identities": len([item for item in identity_risks if item["risk_score"] > 0]),
        "critical": len([item for item in identity_risks if item["severity"] == "Critical" and item["risk_score"] > 0]),
        "high": len([item for item in identity_risks if item["severity"] == "High"]),
        "medium": len([item for item in identity_risks if item["severity"] == "Medium"]),
        "low": len([item for item in identity_risks if item["severity"] == "Low" and item["risk_score"] > 0])
    }

    result = {
        "module": "Identity Risk Engine",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "source": str(FABRIC_FILE),
        "quality_source": str(QUALITY_FILE) if QUALITY_FILE.exists() else None,
        "summary": summary,
        "identity_risks": identity_risks
    }

    json_path = REPORT_DIR / "identity_risk_report.json"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    md_path = generate_markdown_report(result)

    print("[+] Identity Risk Engine completed")
    print(f"[+] JSON Report: {json_path}")
    print(f"[+] Markdown Report: {md_path}")
    print(f"[+] Total Identities: {summary['total_identities']}")
    print(f"[+] Risky Identities: {summary['risky_identities']}")
    print(f"[+] Critical: {summary['critical']}")
    print(f"[+] High: {summary['high']}")
    print(f"[+] Medium: {summary['medium']}")
    print(f"[+] Low: {summary['low']}")

    return result


if __name__ == "__main__":
    run_risk_engine()
