"""
TrustShield — Entra ID Connector (Phase 2)
==========================================
Pulls REAL identity data from Microsoft Entra ID via Microsoft Graph API
and exports it as pipeline-compatible CSV files.

Outputs written to module_identity_fabric/raw/:
  hr_export.csv     — all users: name, email, department, manager, status
  ad_export.csv     — MFA status + days since last sign-in per user
  groups_export.csv — group membership mapping

Required .env variables:
  ENTRA_TENANT_ID      — Azure AD tenant ID (Directory ID)
  ENTRA_CLIENT_ID      — App registration client ID
  ENTRA_CLIENT_SECRET  — App registration client secret value

Required API permissions (Application, admin-consented):
  User.Read.All
  Group.Read.All
  UserAuthenticationMethod.Read.All
  Reports.Read.All
  AuditLog.Read.All
"""

import csv
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import msal
import requests
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR  = BASE_DIR / "module_identity_fabric" / "raw"
RAW_DIR.mkdir(parents=True, exist_ok=True)

TENANT_ID     = os.getenv("ENTRA_TENANT_ID", "")
CLIENT_ID     = os.getenv("ENTRA_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("ENTRA_CLIENT_SECRET", "")
GRAPH_BASE    = "https://graph.microsoft.com/v1.0"
SCOPE         = ["https://graph.microsoft.com/.default"]
DORMANT_THRESHOLD_DAYS = 90


def get_token() -> str:
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        raise EnvironmentError(
            "Missing Entra credentials.\n"
            "Set ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET in .env"
        )
    app = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
        client_credential=CLIENT_SECRET,
    )
    result = app.acquire_token_for_client(scopes=SCOPE)
    if "access_token" not in result:
        err = result.get("error_description", result.get("error", "Unknown"))
        raise RuntimeError(f"Authentication failed: {err}")
    return result["access_token"]


def _graph_get(token, url, params=None):
    headers = {"Authorization": f"Bearer {token}", "ConsistencyLevel": "eventual"}
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _graph_get_all(token, url, params=None):
    items, next_url, cur_params = [], url, params
    while next_url:
        data = _graph_get(token, next_url, cur_params)
        items.extend(data.get("value", []))
        next_url   = data.get("@odata.nextLink")
        cur_params = None
        time.sleep(0.05)
    return items


def fetch_users(token):
    print("  [1/4] Fetching users + sign-in activity...")
    users = _graph_get_all(token, f"{GRAPH_BASE}/users", {
        "$select": ("id,displayName,mail,userPrincipalName,"
                    "department,jobTitle,accountEnabled"),
        "$top": "999",
    })
    print(f"        {len(users)} users found")
    return users


def fetch_manager_upn(token, user_id):
    try:
        data = _graph_get(token, f"{GRAPH_BASE}/users/{user_id}/manager",
                          {"$select": "userPrincipalName"})
        return data.get("userPrincipalName", "")
    except requests.HTTPError:
        return ""


def fetch_mfa_registration_map(token):
    print("  [2/4] Fetching MFA registration status...")
    mfa_map = {}
    try:
        records = _graph_get_all(token, f"{GRAPH_BASE}/reports/credentialUserRegistrationDetails")
        for r in records:
            mfa_map[r.get("userPrincipalName", "")] = r.get("isMfaRegistered", False)
        print(f"        {len(mfa_map)} MFA records (Reports API)")
    except requests.HTTPError as e:
        print(f"        Reports API unavailable ({e.response.status_code}), will use per-user fallback")
    return mfa_map


def fetch_mfa_for_user(token, user_id):
    try:
        data = _graph_get(token, f"{GRAPH_BASE}/users/{user_id}/authentication/methods")
        methods = [m.get("@odata.type", "") for m in data.get("value", [])]
        strong  = [m for m in methods if "password" not in m.lower()]
        return len(strong) > 0
    except requests.HTTPError:
        return False


def fetch_groups(token):
    print("  [3/4] Fetching security groups...")
    groups = _graph_get_all(token, f"{GRAPH_BASE}/groups", {
        "$filter": "securityEnabled eq true",
        "$select": "id,displayName",
        "$top": "999",
    })
    print(f"        {len(groups)} security groups found")
    return groups


def fetch_group_members(token, group_id):
    try:
        members = _graph_get_all(token, f"{GRAPH_BASE}/groups/{group_id}/members",
                                 {"$select": "userPrincipalName", "$top": "999"})
        return [m.get("userPrincipalName", "") for m in members if m.get("userPrincipalName")]
    except requests.HTTPError:
        return []


def _days_since(dt_str):
    if not dt_str:
        return 999
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError):
        return 999


def _write_csv(path, fieldnames, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"        Written: {path.name} ({len(rows)} rows)")


def sync_from_entra(verbose=True) -> bool:
    print("\n" + "=" * 60)
    print("  TrustShield — Entra ID Sync (Phase 2)")
    print("=" * 60)

    try:
        print("\n[Auth] Acquiring token...")
        token = get_token()
        print("[Auth] Token acquired ✓")
    except (EnvironmentError, RuntimeError) as e:
        print(f"[Auth] FAILED: {e}")
        return False

    print("\n[Fetch]")
    users   = fetch_users(token)
    mfa_map = fetch_mfa_registration_map(token)
    groups  = fetch_groups(token)

    print("\n  [4/4] Processing users...")
    hr_rows = []
    ad_rows = []
    group_rows = []

    for i, user in enumerate(users, 1):
        upn     = user.get("userPrincipalName", "")
        email   = user.get("mail") or upn
        name    = user.get("displayName", "Unknown")
        dept    = user.get("department") or "Unknown"
        status  = "Active" if user.get("accountEnabled", True) else "Disabled"

        sign_in = {}
        last_login_days = _days_since(
            sign_in.get("lastSignInDateTime") or
            sign_in.get("lastNonInteractiveSignInDateTime")
        )

        mfa_enabled = mfa_map.get(upn)
        if mfa_enabled is None:
            mfa_enabled = fetch_mfa_for_user(token, user["id"])
            time.sleep(0.05)

        manager_upn = fetch_manager_upn(token, user["id"])

        if verbose and i % 5 == 0:
            print(f"        Processed {i}/{len(users)} users...")

        hr_rows.append({
            "employee_id": user["id"],
            "full_name":   name,
            "email":       email,
            "department":  dept,
            "manager":     manager_upn,
            "status":      status,
        })
        ad_rows.append({
            "samaccountname":  upn.split("@")[0] if "@" in upn else upn,
            "email":           email,
            "mfa_enabled":     str(mfa_enabled).lower(),
            "last_login_days": last_login_days,
        })

    for group in groups:
        members = fetch_group_members(token, group["id"])
        for upn in members:
            group_rows.append({"email": upn, "group_name": group.get("displayName", "")})

    print("\n[Output]")
    _write_csv(RAW_DIR / "hr_export.csv",
               ["employee_id", "full_name", "email", "department", "manager", "status"], hr_rows)
    _write_csv(RAW_DIR / "ad_export.csv",
               ["samaccountname", "email", "mfa_enabled", "last_login_days"], ad_rows)
    _write_csv(RAW_DIR / "groups_export.csv",
               ["email", "group_name"], group_rows)

    no_mfa   = [r for r in ad_rows if r["mfa_enabled"] == "false"]
    dormant  = [r for r in ad_rows if isinstance(r["last_login_days"], int)
                and r["last_login_days"] >= DORMANT_THRESHOLD_DAYS]
    disabled = [r for r in hr_rows if r["status"] == "Disabled"]

    print("\n[Live Governance Findings — Preview]")
    print(f"  MFA not registered : {len(no_mfa)} users")
    print(f"  Dormant (90+ days) : {len(dormant)} users")
    print(f"  Disabled accounts  : {len(disabled)} users")
    print(f"\n  Run full pipeline (Option 1) for complete risk scores.")
    print("=" * 60 + "\n")
    return True


if __name__ == "__main__":
    sync_from_entra()
