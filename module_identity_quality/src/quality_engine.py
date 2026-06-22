import json
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent.parent

FABRIC_FILE = BASE_DIR / "module_identity_fabric" / "normalized" / "identity_fabric.json"
REPORT_DIR = BASE_DIR / "module_identity_quality" / "reports"

REPORT_DIR.mkdir(parents=True, exist_ok=True)


def load_identity_fabric():
    if not FABRIC_FILE.exists():
        raise FileNotFoundError(
            f"Identity fabric not found: {FABRIC_FILE}. Run Module 0 first."
        )

    with open(FABRIC_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def is_empty(value):
    return value is None or str(value).strip() == "" or str(value).lower() == "nan"


def add_issue(issues, severity, issue_type, field, description, impact, recommendation):
    score_penalty = {
        "Critical": 35,
        "High": 25,
        "Medium": 15,
        "Low": 5
    }

    issues.append({
        "severity": severity,
        "issue_type": issue_type,
        "field": field,
        "description": description,
        "impact": impact,
        "recommendation": recommendation,
        "score_penalty": score_penalty.get(severity, 5)
    })


def calculate_confidence(score):
    if score >= 90:
        return "High"
    if score >= 70:
        return "Medium"
    if score >= 40:
        return "Low"
    return "Very Low"


def evaluate_identity(identity, duplicate_emails):
    issues = []
    score = 100

    email = identity.get("email")
    manager = identity.get("manager")
    department = identity.get("department")
    status = str(identity.get("status", "")).lower()
    mfa_enabled = str(identity.get("mfa_enabled", "")).lower()
    last_login_days = identity.get("last_login_days")
    groups = identity.get("groups", [])

    if is_empty(email):
        add_issue(
            issues,
            "Critical",
            "missing_email",
            "email",
            "Identity record has no email address.",
            "IAM correlation may fail because email is commonly used as a join key across HR, AD, Entra ID, and application access datasets.",
            "Populate a verified corporate email address before access governance review."
        )

    if email in duplicate_emails:
        add_issue(
            issues,
            "Critical",
            "duplicate_email",
            "email",
            "Duplicate email address found across identity records.",
            "Duplicate identities can create incorrect access reviews, ownership errors, and inaccurate audit evidence.",
            "Investigate duplicate identity records and define one authoritative identity owner."
        )

    if is_empty(manager):
        add_issue(
            issues,
            "High",
            "missing_manager",
            "manager",
            "Identity record has no manager or accountable owner.",
            "Access reviews and approvals may not have a valid business owner.",
            "Assign a manager or application owner for governance accountability."
        )

    if is_empty(department):
        add_issue(
            issues,
            "Medium",
            "missing_department",
            "department",
            "Identity record has no department.",
            "Department-based access reviews and segregation of duties checks may be incomplete.",
            "Update HR source data with a valid department."
        )

    if status == "terminated" and len(groups) > 0:
        add_issue(
            issues,
            "Critical",
            "terminated_user_with_access",
            "status/groups",
            "Terminated identity still has group memberships.",
            "Leaver process may be incomplete, creating risk of unauthorized access.",
            "Remove all access and validate offboarding controls."
        )

    privileged_keywords = ["admin", "privileged", "database", "domain", "payment"]
    privileged_groups = [
        group for group in groups
        if any(keyword in str(group).lower() for keyword in privileged_keywords)
    ]

    if privileged_groups and mfa_enabled != "true":
        add_issue(
            issues,
            "High",
            "privileged_user_without_mfa",
            "mfa_enabled",
            "Identity has privileged group membership but MFA is not enabled.",
            "Stolen credentials could provide elevated access without an additional verification factor.",
            "Enable MFA and enforce privileged access policy."
        )

    try:
        last_login_days_int = int(last_login_days)
        if last_login_days_int > 180 and len(groups) > 0:
            add_issue(
                issues,
                "High",
                "stale_identity_with_access",
                "last_login_days",
                f"Identity has not logged in for {last_login_days_int} days but still has access.",
                "Dormant access increases the risk of unnoticed compromise or unnecessary entitlement exposure.",
                "Validate business need and remove access if no longer required."
            )
    except (TypeError, ValueError):
        add_issue(
            issues,
            "Medium",
            "invalid_last_login_value",
            "last_login_days",
            "Last login value is missing or not numeric.",
            "Staleness checks cannot be trusted for this identity.",
            "Fix source data format for last login information."
        )

    for issue in issues:
        score -= issue["score_penalty"]

    score = max(score, 0)

    return {
        "identity_id": identity.get("identity_id"),
        "email": email,
        "name": identity.get("name"),
        "data_quality_score": score,
        "confidence": calculate_confidence(score),
        "issue_count": len(issues),
        "issues": issues
    }


def generate_markdown_report(result):
    report_path = REPORT_DIR / "identity_quality_report.md"

    lines = []
    lines.append("# TrustShield IAM AI - Identity Data Quality Report")
    lines.append("")
    lines.append(f"Generated: {result['generated_at']}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Total Identities Reviewed: {result['summary']['total_identities']}")
    lines.append(f"- Identities With Issues: {result['summary']['identities_with_issues']}")
    lines.append(f"- Critical Issues: {result['summary']['critical_issues']}")
    lines.append(f"- High Issues: {result['summary']['high_issues']}")
    lines.append(f"- Average Data Quality Score: {result['summary']['average_quality_score']}")
    lines.append("")
    lines.append("## Identity Findings")
    lines.append("")

    for identity in result["identity_quality"]:
        if identity["issue_count"] == 0:
            continue

        lines.append(f"### {identity['email']}")
        lines.append(f"- Identity ID: {identity['identity_id']}")
        lines.append(f"- Data Quality Score: {identity['data_quality_score']}")
        lines.append(f"- Confidence: {identity['confidence']}")
        lines.append(f"- Issue Count: {identity['issue_count']}")
        lines.append("")

        for issue in identity["issues"]:
            lines.append(f"#### {issue['severity']} - {issue['issue_type']}")
            lines.append(f"- Field: {issue['field']}")
            lines.append(f"- Description: {issue['description']}")
            lines.append(f"- Impact: {issue['impact']}")
            lines.append(f"- Recommendation: {issue['recommendation']}")
            lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def run_quality_engine():
    fabric = load_identity_fabric()
    identities = fabric.get("identities", [])

    emails = [identity.get("email") for identity in identities if not is_empty(identity.get("email"))]
    duplicate_emails = {email for email in emails if emails.count(email) > 1}

    identity_quality = [
        evaluate_identity(identity, duplicate_emails)
        for identity in identities
    ]

    critical_issues = 0
    high_issues = 0

    for identity in identity_quality:
        for issue in identity["issues"]:
            if issue["severity"] == "Critical":
                critical_issues += 1
            if issue["severity"] == "High":
                high_issues += 1

    average_score = 0
    if identity_quality:
        average_score = round(
            sum(item["data_quality_score"] for item in identity_quality) / len(identity_quality),
            2
        )

    summary = {
        "total_identities": len(identity_quality),
        "identities_with_issues": len([item for item in identity_quality if item["issue_count"] > 0]),
        "critical_issues": critical_issues,
        "high_issues": high_issues,
        "average_quality_score": average_score
    }

    result = {
        "module": "Identity Data Quality & Confidence Engine",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "source": str(FABRIC_FILE),
        "summary": summary,
        "identity_quality": identity_quality
    }

    json_path = REPORT_DIR / "identity_quality_report.json"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    md_path = generate_markdown_report(result)

    print("[+] Identity Data Quality Engine completed")
    print(f"[+] JSON Report: {json_path}")
    print(f"[+] Markdown Report: {md_path}")
    print(f"[+] Total Identities: {summary['total_identities']}")
    print(f"[+] Identities With Issues: {summary['identities_with_issues']}")
    print(f"[+] Critical Issues: {summary['critical_issues']}")
    print(f"[+] High Issues: {summary['high_issues']}")
    print(f"[+] Average Quality Score: {summary['average_quality_score']}")

    return result


if __name__ == "__main__":
    run_quality_engine()
