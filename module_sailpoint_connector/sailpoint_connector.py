"""
TrustShield — SailPoint Identity Security Cloud Connector (Phase 3)
===================================================================
Connects to SailPoint ISC via the official Python SDK.
Runs in two modes:

  MOCK mode  (default) — uses a realistic 50-identity enterprise dataset
                         with pre-seeded IAM problems for demo and testing.
  LIVE mode            — connects to a real ISC tenant using credentials
                         from .env. Switch by setting SAILPOINT_MOCK=false.

IAM problems seeded in mock data:
  - Orphan accounts (SailPoint account, no HR record)
  - SoD violations (Finance + Audit access on same identity)
  - Terminated users with active ISC accounts
  - Stale entitlements (dormant users with privileged access)
  - Missing manager assignments
  - MFA not registered

Outputs to module_identity_fabric/raw/:
  hr_export.csv, ad_export.csv, groups_export.csv

Additional SailPoint-specific output:
  sailpoint_findings.csv — orphans, SoD, stale entitlements
"""

import csv
import json
import os
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR  = Path(__file__).resolve().parent.parent
RAW_DIR   = BASE_DIR / "module_identity_fabric" / "raw"
SP_DIR    = BASE_DIR / "module_sailpoint_connector" / "data"
RAW_DIR.mkdir(parents=True, exist_ok=True)
SP_DIR.mkdir(parents=True, exist_ok=True)

MOCK_MODE = os.getenv("SAILPOINT_MOCK", "true").lower() != "false"

TENANT_URL    = os.getenv("SAILPOINT_TENANT_URL", "")
CLIENT_ID     = os.getenv("SAILPOINT_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("SAILPOINT_CLIENT_SECRET", "")


# ══════════════════════════════════════════════════════════════════
# MOCK DATA GENERATOR
# Enterprise: GlobalBank Corp — 50 identities, 6 departments
# Pre-seeded with real IAM problems
# ══════════════════════════════════════════════════════════════════

DEPARTMENTS = ["Finance", "IT", "HR", "Engineering", "Sales", "Audit"]

MANAGERS = {
    "Finance":     "sarah.chen@globalbankcorp.com",
    "IT":          "james.okafor@globalbankcorp.com",
    "HR":          "linda.brooks@globalbankcorp.com",
    "Engineering": "rafael.santos@globalbankcorp.com",
    "Sales":       "priya.mehta@globalbankcorp.com",
    "Audit":       "thomas.walsh@globalbankcorp.com",
}

ACCESS_PROFILES = {
    "Finance":     ["Finance-Systems", "SAP-Finance", "Treasury-Portal"],
    "IT":          ["IT-Admin", "ServiceDesk", "Azure-Admin", "Domain-Admins"],
    "HR":          ["HRIS-Access", "Payroll-System", "Employee-Portal"],
    "Engineering": ["Dev-Environment", "GitHub-Enterprise", "AWS-Dev", "Jira-Full"],
    "Sales":       ["CRM-Access", "Sales-Portal", "Salesforce"],
    "Audit":       ["Audit-Portal", "Finance-ReadOnly", "Compliance-Reports"],
}

PRIVILEGED_GROUPS = ["Domain-Admins", "Azure-Admin", "AWS-Admin", "IT-Admin", "SAP-Finance"]

IDENTITIES_RAW = [
    # Normal active employees
    {"name": "Sarah Chen",       "dept": "Finance",     "status": "Active",     "mfa": True,  "days": 3},
    {"name": "James Okafor",     "dept": "IT",          "status": "Active",     "mfa": True,  "days": 1},
    {"name": "Linda Brooks",     "dept": "HR",          "status": "Active",     "mfa": True,  "days": 2},
    {"name": "Rafael Santos",    "dept": "Engineering", "status": "Active",     "mfa": True,  "days": 4},
    {"name": "Priya Mehta",      "dept": "Sales",       "status": "Active",     "mfa": True,  "days": 5},
    {"name": "Thomas Walsh",     "dept": "Audit",       "status": "Active",     "mfa": True,  "days": 2},
    {"name": "Emma Wilson",      "dept": "Finance",     "status": "Active",     "mfa": True,  "days": 7},
    {"name": "Daniel Kim",       "dept": "IT",          "status": "Active",     "mfa": True,  "days": 3},
    {"name": "Aisha Patel",      "dept": "HR",          "status": "Active",     "mfa": True,  "days": 6},
    {"name": "Marco Ferrari",    "dept": "Engineering", "status": "Active",     "mfa": True,  "days": 2},
    {"name": "Chloe Martin",     "dept": "Sales",       "status": "Active",     "mfa": True,  "days": 8},
    {"name": "Kevin Nguyen",     "dept": "Finance",     "status": "Active",     "mfa": True,  "days": 4},
    {"name": "Sofia Rossi",      "dept": "Engineering", "status": "Active",     "mfa": True,  "days": 3},
    {"name": "Liam Johnson",     "dept": "IT",          "status": "Active",     "mfa": True,  "days": 1},
    {"name": "Amara Diallo",     "dept": "HR",          "status": "Active",     "mfa": True,  "days": 9},
    # MFA not registered (real finding)
    {"name": "Robert Hayes",     "dept": "Finance",     "status": "Active",     "mfa": False, "days": 12},
    {"name": "Jessica Turner",   "dept": "Sales",       "status": "Active",     "mfa": False, "days": 18},
    {"name": "Michael Brown",    "dept": "Engineering", "status": "Active",     "mfa": False, "days": 6},
    {"name": "Natalie Cruz",     "dept": "HR",          "status": "Active",     "mfa": False, "days": 22},
    {"name": "David Park",       "dept": "Finance",     "status": "Active",     "mfa": False, "days": 15},
    # Dormant accounts (real finding)
    {"name": "Andrew Scott",     "dept": "IT",          "status": "Active",     "mfa": True,  "days": 120},
    {"name": "Rachel Green",     "dept": "Finance",     "status": "Active",     "mfa": True,  "days": 145},
    {"name": "Peter Morrison",   "dept": "Sales",       "status": "Active",     "mfa": False, "days": 200},
    {"name": "Fiona Campbell",   "dept": "Engineering", "status": "Active",     "mfa": True,  "days": 95},
    # Terminated users still active in SailPoint (real finding)
    {"name": "Steven Clark",     "dept": "Finance",     "status": "Terminated", "mfa": False, "days": 180},
    {"name": "Maria Lopez",      "dept": "IT",          "status": "Terminated", "mfa": False, "days": 210},
    {"name": "John Williams",    "dept": "Engineering", "status": "Terminated", "mfa": False, "days": 155},
    # Missing manager
    {"name": "Oliver Reed",      "dept": "Sales",       "status": "Active",     "mfa": True,  "days": 14, "no_manager": True},
    {"name": "Grace Kelly",      "dept": "Finance",     "status": "Active",     "mfa": False, "days": 30, "no_manager": True},
    # SoD violations — Finance AND Audit access (real finding)
    {"name": "Nathan Fox",       "dept": "Finance",     "status": "Active",     "mfa": True,  "days": 5,  "sod": True},
    {"name": "Isabella Stone",   "dept": "Finance",     "status": "Active",     "mfa": True,  "days": 3,  "sod": True},
    # Orphan accounts — in SailPoint, no HR record (real finding)
    {"name": "svc_backup01",     "dept": "IT",          "status": "Active",     "mfa": False, "days": 999, "orphan": True},
    {"name": "svc_reporting",    "dept": "IT",          "status": "Active",     "mfa": False, "days": 999, "orphan": True},
    {"name": "app_finance_svc",  "dept": "Finance",     "status": "Active",     "mfa": False, "days": 999, "orphan": True},
    # Regular employees filling out to 50
    {"name": "Charlotte Evans",  "dept": "Sales",       "status": "Active",     "mfa": True,  "days": 11},
    {"name": "Benjamin Turner",  "dept": "Finance",     "status": "Active",     "mfa": True,  "days": 6},
    {"name": "Mia Robinson",     "dept": "HR",          "status": "Active",     "mfa": True,  "days": 4},
    {"name": "Ethan White",      "dept": "Engineering", "status": "Active",     "mfa": True,  "days": 7},
    {"name": "Ava Thompson",     "dept": "Audit",       "status": "Active",     "mfa": True,  "days": 3},
    {"name": "Noah Harris",      "dept": "IT",          "status": "Active",     "mfa": True,  "days": 2},
    {"name": "Isabella Clark",   "dept": "Finance",     "status": "Active",     "mfa": True,  "days": 8},
    {"name": "Lucas Lewis",      "dept": "Sales",       "status": "Active",     "mfa": True,  "days": 5},
    {"name": "Harper Lee",       "dept": "HR",          "status": "Active",     "mfa": True,  "days": 10},
    {"name": "Mason Hall",       "dept": "Engineering", "status": "Active",     "mfa": True,  "days": 1},
    {"name": "Ella Young",       "dept": "Audit",       "status": "Active",     "mfa": True,  "days": 6},
    {"name": "Logan King",       "dept": "IT",          "status": "Active",     "mfa": True,  "days": 3},
    {"name": "Abigail Wright",   "dept": "Finance",     "status": "Active",     "mfa": True,  "days": 9},
    {"name": "Jackson Scott",    "dept": "Engineering", "status": "Active",     "mfa": True,  "days": 4},
    {"name": "Emily Adams",      "dept": "Sales",       "status": "Active",     "mfa": True,  "days": 7},
]


def _make_email(name: str) -> str:
    clean = name.lower().replace(" ", ".").replace("_", ".")
    return f"{clean}@globalbankcorp.com"


def _make_sam(email: str) -> str:
    return email.split("@")[0].replace(".", "_")[:20]


def generate_mock_data() -> tuple:
    """Generate realistic enterprise identity dataset with pre-seeded IAM problems."""
    hr_rows, ad_rows, group_rows, sp_findings = [], [], [], []

    for idx, identity in enumerate(IDENTITIES_RAW, 1):
        name    = identity["name"]
        dept    = identity["dept"]
        status  = identity["status"]
        mfa     = identity["mfa"]
        days    = identity["days"]
        orphan  = identity.get("orphan", False)
        sod     = identity.get("sod", False)
        no_mgr  = identity.get("no_manager", False)

        email  = _make_email(name)
        sam    = _make_sam(email)
        emp_id = f"GBC{idx:04d}"
        manager = "" if (no_mgr or orphan) else MANAGERS.get(dept, "")

        # HR row (orphans have no HR record — skip them from HR export)
        if not orphan:
            hr_rows.append({
                "employee_id": emp_id,
                "full_name":   name,
                "email":       email,
                "department":  dept,
                "manager":     manager,
                "status":      status,
            })

        # AD row
        ad_rows.append({
            "samaccountname":  sam,
            "email":           email,
            "mfa_enabled":     str(mfa).lower(),
            "last_login_days": days,
        })

        # Groups
        profiles = ACCESS_PROFILES.get(dept, [])
        for profile in profiles:
            group_rows.append({"email": email, "group_name": profile})

        # SoD violation — add Audit access to Finance users flagged for SoD
        if sod:
            for audit_profile in ACCESS_PROFILES["Audit"]:
                group_rows.append({"email": email, "group_name": audit_profile})

        # Orphan accounts get broad IT access
        if orphan:
            for profile in ACCESS_PROFILES["IT"]:
                group_rows.append({"email": email, "group_name": profile})

        # SailPoint-specific findings
        if orphan:
            sp_findings.append({
                "finding_type": "ORPHAN_ACCOUNT",
                "email":        email,
                "name":         name,
                "department":   dept,
                "detail":       "Account exists in SailPoint with no matching HR record. Likely a service account with no owner.",
                "severity":     "High",
            })

        if sod:
            sp_findings.append({
                "finding_type": "SOD_VIOLATION",
                "email":        email,
                "name":         name,
                "department":   dept,
                "detail":       "Identity has both Finance-Systems and Audit-Portal access. Finance + Audit combination violates Separation of Duties policy.",
                "severity":     "Critical",
            })

        if status == "Terminated" and days < 999:
            sp_findings.append({
                "finding_type": "TERMINATED_WITH_ACCESS",
                "email":        email,
                "name":         name,
                "department":   dept,
                "detail":       f"Identity marked Terminated but account remains active in SailPoint with {len(profiles)} access profiles. Last login: {days} days ago.",
                "severity":     "Critical",
            })

        if days >= 90 and status == "Active" and not orphan:
            sp_findings.append({
                "finding_type": "STALE_ENTITLEMENT",
                "email":        email,
                "name":         name,
                "department":   dept,
                "detail":       f"Active account with no login for {days} days. Entitlements should be reviewed and recertified.",
                "severity":     "High" if days < 180 else "Critical",
            })

        if no_mgr and not orphan:
            sp_findings.append({
                "finding_type": "MISSING_MANAGER",
                "email":        email,
                "name":         name,
                "department":   dept,
                "detail":       "No manager assigned. Access reviews cannot be delegated. Account will be excluded from certification campaigns.",
                "severity":     "Medium",
            })

    return hr_rows, ad_rows, group_rows, sp_findings


# ══════════════════════════════════════════════════════════════════
# LIVE MODE (SailPoint ISC via SDK)
# ══════════════════════════════════════════════════════════════════

def sync_live() -> tuple:
    """Pull real data from SailPoint ISC using the Python SDK."""
    try:
        import sailpoint
        import sailpoint.v2024
        from sailpoint.v2024.api.identities_api import IdentitiesApi
        from sailpoint.v2024.api.accounts_api import AccountsApi
        from sailpoint.v2024.api.access_profiles_api import AccessProfilesApi
    except ImportError:
        print("  [ERROR] sailpoint SDK not installed. Run: pip install sailpoint")
        return [], [], [], []

    configuration = sailpoint.v2024.Configuration(
        host=f"https://{TENANT_URL}.api.identitynow.com",
    )
    configuration.access_token = _get_live_token()

    hr_rows, ad_rows, group_rows, sp_findings = [], [], [], []

    with sailpoint.v2024.ApiClient(configuration) as api_client:
        # Identities
        identities_api = IdentitiesApi(api_client)
        identities = identities_api.list_identities(limit=250)

        for identity in identities:
            email  = identity.email or ""
            name   = identity.display_name or ""
            dept   = (identity.attributes or {}).get("department", "Unknown")
            status = "Active" if identity.enabled else "Disabled"
            manager_email = ""

            if identity.manager_ref:
                manager_email = identity.manager_ref.email or ""

            hr_rows.append({
                "employee_id": identity.id,
                "full_name":   name,
                "email":       email,
                "department":  dept,
                "manager":     manager_email,
                "status":      status,
            })

            ad_rows.append({
                "samaccountname":  email.split("@")[0] if email else identity.id[:20],
                "email":           email,
                "mfa_enabled":     "true",
                "last_login_days": 30,
            })

    return hr_rows, ad_rows, group_rows, sp_findings


def _get_live_token() -> str:
    import requests
    resp = requests.post(
        f"https://{TENANT_URL}.identitynow.com/oauth/token",
        data={
            "grant_type":    "client_credentials",
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


# ══════════════════════════════════════════════════════════════════
# CSV WRITERS
# ══════════════════════════════════════════════════════════════════

def _write_csv(path: Path, fieldnames: list, rows: list):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"        Written: {path.name} ({len(rows)} rows)")


# ══════════════════════════════════════════════════════════════════
# MAIN SYNC
# ══════════════════════════════════════════════════════════════════

def sync_from_sailpoint(verbose: bool = True) -> bool:
    print("\n" + "=" * 60)
    print("  TrustShield — SailPoint ISC Sync (Phase 3)")
    if MOCK_MODE:
        print("  Mode: MOCK (GlobalBank Corp — 50 identities)")
    else:
        print(f"  Mode: LIVE ({TENANT_URL}.identitynow.com)")
    print("=" * 60)

    if MOCK_MODE:
        print("\n[Data] Generating enterprise mock dataset...")
        hr_rows, ad_rows, group_rows, sp_findings = generate_mock_data()
    else:
        if not all([TENANT_URL, CLIENT_ID, CLIENT_SECRET]):
            print("[ERROR] Set SAILPOINT_TENANT_URL, SAILPOINT_CLIENT_ID, SAILPOINT_CLIENT_SECRET in .env")
            return False
        print("\n[Data] Connecting to SailPoint ISC...")
        hr_rows, ad_rows, group_rows, sp_findings = sync_live()

    print(f"\n[Output]")
    _write_csv(RAW_DIR / "hr_export.csv",
               ["employee_id", "full_name", "email", "department", "manager", "status"], hr_rows)
    _write_csv(RAW_DIR / "ad_export.csv",
               ["samaccountname", "email", "mfa_enabled", "last_login_days"], ad_rows)
    _write_csv(RAW_DIR / "groups_export.csv",
               ["email", "group_name"], group_rows)
    _write_csv(SP_DIR / "sailpoint_findings.csv",
               ["finding_type", "email", "name", "department", "detail", "severity"], sp_findings)

    # Findings summary
    sod        = [f for f in sp_findings if f["finding_type"] == "SOD_VIOLATION"]
    orphans    = [f for f in sp_findings if f["finding_type"] == "ORPHAN_ACCOUNT"]
    terminated = [f for f in sp_findings if f["finding_type"] == "TERMINATED_WITH_ACCESS"]
    stale      = [f for f in sp_findings if f["finding_type"] == "STALE_ENTITLEMENT"]
    no_mgr     = [f for f in sp_findings if f["finding_type"] == "MISSING_MANAGER"]
    no_mfa     = [r for r in ad_rows if r["mfa_enabled"] == "false"]

    print(f"\n[SailPoint Governance Findings]")
    print(f"  SoD Violations (Critical)    : {len(sod)}")
    print(f"  Terminated with Access (Crit): {len(terminated)}")
    print(f"  Orphan Accounts (High)       : {len(orphans)}")
    print(f"  Stale Entitlements (High)    : {len(stale)}")
    print(f"  Missing Manager (Medium)     : {len(no_mgr)}")
    print(f"  No MFA Registered            : {len(no_mfa)}")
    print(f"  Total identities loaded      : {len(hr_rows) + len(orphans)}")
    print(f"\n  Run pipeline (Option 1) to get full risk scores.")
    print("=" * 60 + "\n")
    return True


if __name__ == "__main__":
    sync_from_sailpoint()
