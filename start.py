import sqlite3
import subprocess
from pathlib import Path
from module_entra_connector.entra_connector import sync_from_entra
from module_sailpoint_connector.sailpoint_connector import sync_from_sailpoint

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "trustshield.db"

PIPELINE = [
    ("Identity Fabric Service", "python3 module_identity_fabric/src/fabric_engine.py"),
    ("Identity Quality Service", "python3 module_identity_quality/src/quality_engine.py"),
    ("Identity Risk Service", "python3 module_identity_risk/src/risk_engine.py"),
    ("Access Review Service", "python3 module_access_review/src/access_review_engine.py"),
    ("Decision Engine", "python3 module_decision_engine/src/decision_engine.py"),
    ("Evidence Vault", "python3 module_evidence_vault/src/evidence_vault.py"),
    ("Quantum Integrity Vault", "python3 module_quantum_integrity/src/quantum_integrity_vault.py"),
    ("Data Store Sync", "python3 module_data_store/src/data_store.py"),
]


def run_command(name, command):
    print(f"\n[RUNNING] {name}")
    result = subprocess.run(command, shell=True, cwd=BASE_DIR, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[FAILED] {name}")
        print(result.stderr)
        return False

    print(f"[OK] {name}")
    if result.stdout.strip():
        print(result.stdout.strip())
    return True


def db_connect():
    if not DB_FILE.exists():
        print("\nDatabase not found. Run analysis first.")
        return None
    return sqlite3.connect(DB_FILE)


def run_full_pipeline():
    print("\n======================================")
    print(" TrustShield Full Governance Pipeline")
    print("======================================")

    for name, command in PIPELINE:
        if not run_command(name, command):
            print("\nPipeline stopped.")
            return

    print("\n[OK] Full governance pipeline completed.")


# ==================================================
# DATA INTAKE
# ==================================================

def add_identity_manually():
    print("\nAdd New Raw Identity")
    print("-" * 40)

    employee_id = input("Employee ID: ").strip()
    full_name = input("Full Name: ").strip()
    email = input("Email: ").strip()
    department = input("Department: ").strip()
    manager = input("Manager Email, blank if none: ").strip()
    status = input("Status Active/Terminated/Disabled: ").strip() or "Active"

    samaccountname = input("AD Username / samAccountName: ").strip()
    mfa_enabled = input("MFA enabled? true/false: ").strip().lower() or "false"
    last_login_days = input("Last login days: ").strip() or "999"

    groups_raw = input("Groups comma-separated: ").strip()
    groups = [g.strip() for g in groups_raw.split(",") if g.strip()]

    raw_dir = BASE_DIR / "module_identity_fabric" / "raw"

    with open(raw_dir / "hr_export.csv", "a", encoding="utf-8") as f:
        f.write(f"\n{employee_id},{full_name},{email},{department},{manager},{status}")

    with open(raw_dir / "ad_export.csv", "a", encoding="utf-8") as f:
        f.write(f"\n{samaccountname},{email},{mfa_enabled},{last_login_days}")

    with open(raw_dir / "groups_export.csv", "a", encoding="utf-8") as f:
        for group in groups:
            f.write(f"\n{email},{group}")

    print("\n[OK] Raw identity added.")
    print("[NEXT] Run Full Analysis Pipeline to process it.")


def view_raw_file(filename):
    path = BASE_DIR / "module_identity_fabric" / "raw" / filename

    if not path.exists():
        print(f"\nFile not found: {path}")
        return

    print(f"\n{filename}")
    print("-" * 60)
    print(path.read_text())



# ==================================================
# ENTRA ID LIVE SYNC
# ==================================================

def sync_sailpoint_and_run():
    print("\n[SailPoint] Loading identity data from SailPoint ISC...")
    success = sync_from_sailpoint()
    if success:
        print("\n[OK] SailPoint data loaded. Running full governance pipeline...")
        run_full_pipeline()
    else:
        print("\n[FAILED] Sync failed. Check .env credentials or SAILPOINT_MOCK setting.")

def sync_entra_and_run():
    print("\n[Entra ID] Pulling live identity data from Microsoft Entra ID...")
    success = sync_from_entra()
    if success:
        print("\n[OK] Live data synced. Running full governance pipeline...")
        run_full_pipeline()
    else:
        print("\n[FAILED] Sync failed. Check .env credentials.")

def analyze_new_data_menu():
    while True:
        print("""
======================================
 Analyze New Data
======================================
0. Sync from Microsoft Entra ID  [LIVE DATA]
S. Sync from SailPoint ISC       [ENTERPRISE DATA]
1. Add Identity Manually
2. View Raw HR Data
3. View Raw AD Data
4. View Raw Group Data
5. Run Full Analysis Pipeline
6. Back
======================================
""")

        choice = input("Select option: ").strip()

        if choice == "0":
            sync_entra_and_run()
        elif choice == "s":
            sync_sailpoint_and_run()
        elif choice == "1":
            add_identity_manually()

        elif choice == "2":
            view_raw_file("hr_export.csv")

        elif choice == "3":
            view_raw_file("ad_export.csv")

        elif choice == "4":
            view_raw_file("groups_export.csv")

        elif choice == "5":
            run_full_pipeline()

        elif choice == "6":
            break

        else:
            print("Invalid option.")


# ==================================================
# VIEW / INVESTIGATE
# ==================================================

def view_all_identities():
    conn = db_connect()
    if not conn:
        return

    cur = conn.cursor()
    cur.execute("""
        SELECT identity_id, name, email, department, status, mfa_enabled, last_login_days
        FROM identities
        ORDER BY identity_id
    """)

    rows = cur.fetchall()
    print(f"\nExisting Identities: {len(rows)}\n")

    for r in rows:
        mfa = "Enabled" if r[5] == 1 else "Disabled"
        print(f"{r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} | MFA: {mfa} | Last Login: {r[6]} days")

    conn.close()


def investigate_identity():
    keyword = input("\nEnter name/email/id to investigate: ").lower().strip()

    conn = db_connect()
    if not conn:
        return

    cur = conn.cursor()
    cur.execute("""
        SELECT identity_id, name, email, department, manager, status, mfa_enabled, last_login_days
        FROM identities
        WHERE LOWER(name) LIKE ? OR LOWER(email) LIKE ? OR CAST(identity_id AS TEXT)=?
        LIMIT 1
    """, (f"%{keyword}%", f"%{keyword}%", keyword))

    identity = cur.fetchone()

    if not identity:
        print("\nNo identity found.")
        conn.close()
        return

    email = identity[2]
    mfa = "Enabled" if identity[6] == 1 else "Disabled"

    print("\n======================================")
    print(" Identity Investigation")
    print("======================================")
    print(f"ID: {identity[0]}")
    print(f"Name: {identity[1]}")
    print(f"Email: {identity[2]}")
    print(f"Department: {identity[3]}")
    print(f"Manager: {identity[4]}")
    print(f"Status: {identity[5]}")
    print(f"MFA: {mfa}")
    print(f"Last Login Days: {identity[7]}")

    cur.execute("""
        SELECT severity, risk_score, recommendation
        FROM risk_findings
        WHERE email=?
    """, (email,))

    risk = cur.fetchone()

    print("\nRisk Profile")
    print("-" * 40)

    if risk:
        print(f"Severity: {risk[0]}")
        print(f"Risk Score: {risk[1]}")
        print(f"Recommendation: {risk[2]}")
    else:
        print("No risk finding found.")

    conn.close()
    remediation_menu(email)


def identity_explorer_menu():
    while True:
        print("""
======================================
 Identity Explorer
======================================
1. View All Identities
2. Investigate Identity
3. Back
======================================
""")

        choice = input("Select option: ").strip()

        if choice == "1":
            view_all_identities()

        elif choice == "2":
            investigate_identity()

        elif choice == "3":
            break

        else:
            print("Invalid option.")


# ==================================================
# PROBLEM FINDING
# ==================================================

def users_without_mfa():
    conn = db_connect()
    if not conn:
        return

    cur = conn.cursor()
    cur.execute("""
        SELECT identity_id, name, email, department, status
        FROM identities
        WHERE mfa_enabled = 0
        ORDER BY department, name
    """)

    rows = cur.fetchall()
    print("\nUsers Without MFA\n")

    for r in rows:
        print(f"{r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]}")

    conn.close()


def critical_identities():
    conn = db_connect()
    if not conn:
        return

    cur = conn.cursor()
    cur.execute("""
        SELECT i.identity_id, i.name, i.email, i.department, r.risk_score, r.recommendation
        FROM risk_findings r
        JOIN identities i ON r.email = i.email
        WHERE r.severity='Critical'
        ORDER BY r.risk_score DESC
    """)

    rows = cur.fetchall()
    print("\nCritical Identities\n")

    for r in rows:
        print("-" * 60)
        print(f"ID: {r[0]}")
        print(f"Name: {r[1]}")
        print(f"Email: {r[2]}")
        print(f"Department: {r[3]}")
        print(f"Risk Score: {r[4]}")
        print(f"Recommendation: {r[5]}")

    conn.close()


def dormant_accounts():
    conn = db_connect()
    if not conn:
        return

    cur = conn.cursor()
    cur.execute("""
        SELECT name, email, department, status, last_login_days
        FROM identities
        WHERE last_login_days >= 90
        ORDER BY last_login_days DESC
    """)

    rows = cur.fetchall()
    print("\nDormant Accounts >= 90 Days\n")

    for r in rows:
        print(f"- {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} days")

    conn.close()


def terminated_users_with_access():
    conn = db_connect()
    if not conn:
        return

    cur = conn.cursor()
    cur.execute("""
        SELECT i.name, i.email, i.status, r.severity, r.risk_score
        FROM identities i
        JOIN risk_findings r ON i.email = r.email
        WHERE LOWER(i.status)='terminated'
    """)

    rows = cur.fetchall()
    print("\nTerminated Users With Access Risk\n")

    for r in rows:
        print(f"- {r[0]} | {r[1]} | {r[2]} | {r[3]} | Score={r[4]}")

    conn.close()


def high_risk_departments():
    conn = db_connect()
    if not conn:
        return

    cur = conn.cursor()
    cur.execute("""
        SELECT i.department, COUNT(*) AS risky_count
        FROM identities i
        JOIN risk_findings r ON i.email = r.email
        WHERE r.risk_score > 0
        GROUP BY i.department
        ORDER BY risky_count DESC
    """)

    rows = cur.fetchall()
    print("\nHigh Risk Departments\n")

    for r in rows:
        print(f"- {r[0]}: {r[1]} risky identities")

    conn.close()


def find_problems_menu():
    while True:
        print("""
======================================
 Risk Investigation Center
======================================
1. Users Without MFA
2. Critical Identities
3. Dormant Accounts
4. Terminated Users With Access
5. High Risk Departments
6. Back
======================================
""")

        choice = input("Select option: ").strip()

        if choice == "1":
            users_without_mfa()
            target = input("\nEnter email to remediate, or press Enter to skip: ").strip()
            if target:
                remediation_menu(target)

        elif choice == "2":
            critical_identities()
            target = input("\nEnter email to remediate, or press Enter to skip: ").strip()
            if target:
                remediation_menu(target)

        elif choice == "3":
            dormant_accounts()
            target = input("\nEnter email to remediate, or press Enter to skip: ").strip()
            if target:
                remediation_menu(target)

        elif choice == "4":
            terminated_users_with_access()
            target = input("\nEnter email to remediate, or press Enter to skip: ").strip()
            if target:
                remediation_menu(target)

        elif choice == "5":
            high_risk_departments()
            target = input("\nEnter email to investigate/remediate, or press Enter to skip: ").strip()
            if target:
                remediation_menu(target)

        elif choice == "6":
            break

        else:
            print("Invalid option.")


# ==================================================
# REMEDIATION
# ==================================================

def update_raw_ad_mfa(email, new_value):
    ad_file = BASE_DIR / "module_identity_fabric" / "raw" / "ad_export.csv"
    lines = ad_file.read_text().splitlines()
    updated = []

    for line in lines:
        if line.startswith("samaccountname,email"):
            updated.append(line)
            continue

        parts = line.split(",")

        if len(parts) >= 4 and parts[1].strip().lower() == email.lower():
            parts[2] = new_value
            updated.append(",".join(parts))
        else:
            updated.append(line)

    ad_file.write_text("\n".join(updated) + "\n")


def update_raw_hr_manager(email, manager):
    hr_file = BASE_DIR / "module_identity_fabric" / "raw" / "hr_export.csv"
    lines = hr_file.read_text().splitlines()
    updated = []

    for line in lines:
        if line.startswith("employee_id,full_name"):
            updated.append(line)
            continue

        parts = line.split(",")

        if len(parts) >= 6 and parts[2].strip().lower() == email.lower():
            parts[4] = manager
            updated.append(",".join(parts))
        else:
            updated.append(line)

    hr_file.write_text("\n".join(updated) + "\n")


def update_raw_hr_status(email, status):
    hr_file = BASE_DIR / "module_identity_fabric" / "raw" / "hr_export.csv"
    lines = hr_file.read_text().splitlines()
    updated = []

    for line in lines:
        if line.startswith("employee_id,full_name"):
            updated.append(line)
            continue

        parts = line.split(",")

        if len(parts) >= 6 and parts[2].strip().lower() == email.lower():
            parts[5] = status
            updated.append(",".join(parts))
        else:
            updated.append(line)

    hr_file.write_text("\n".join(updated) + "\n")


def remove_raw_groups(email):
    groups_file = BASE_DIR / "module_identity_fabric" / "raw" / "groups_export.csv"
    lines = groups_file.read_text().splitlines()
    updated = []

    for line in lines:
        if line.startswith("email,group_name"):
            updated.append(line)
            continue

        parts = line.split(",")

        if len(parts) >= 2 and parts[0].strip().lower() == email.lower():
            continue

        updated.append(line)

    groups_file.write_text("\n".join(updated) + "\n")


def remove_privileged_groups(email):
    groups_file = BASE_DIR / "module_identity_fabric" / "raw" / "groups_export.csv"

    privileged_keywords = [
        "admin",
        "domain",
        "privileged",
        "operator",
        "backup",
        "database"
    ]

    lines = groups_file.read_text().splitlines()
    updated = []

    for line in lines:
        if line.startswith("email,group_name"):
            updated.append(line)
            continue

        parts = line.split(",")

        if len(parts) < 2:
            updated.append(line)
            continue

        row_email = parts[0].strip().lower()
        group_name = parts[1].strip().lower()

        if row_email == email.lower():
            if any(keyword in group_name for keyword in privileged_keywords):
                continue

        updated.append(line)

    groups_file.write_text("\n".join(updated) + "\n")
    print("\n[OK] Privileged groups removed.")


def create_manual_review(email):
    print(f"\n[OK] Governance review created for {email}")
    print("[SIMULATION] Review queued for manager approval.")


def generate_remediation_evidence(email):
    print(f"\n[OK] Remediation evidence generated for {email}")
    print("[SIMULATION] Evidence attached to audit trail.")


def remediation_menu(email):
    while True:
        print(f"""
======================================
 Remediation Center
 Target: {email}
======================================
1. Enable MFA
2. Assign Manager
3. Disable Account
4. Remove All Group Access
5. Remove Privileged Access
6. Create Governance Review
7. Generate Evidence
8. Re-run Full Pipeline
9. Back
======================================
""")

        choice = input("Select action: ").strip()

        if choice == "1":
            update_raw_ad_mfa(email, "true")
            print("\n[OK] MFA enabled in raw AD export.")
            print("[NEXT] Run option 8 to recalculate risk.")

        elif choice == "2":
            manager = input("Enter manager email: ").strip()
            update_raw_hr_manager(email, manager)
            print("\n[OK] Manager assigned in raw HR export.")
            print("[NEXT] Run option 8 to recalculate risk.")

        elif choice == "3":
            update_raw_hr_status(email, "Disabled")
            print("\n[OK] Account status changed to Disabled in raw HR export.")
            print("[NEXT] Run option 8 to recalculate risk.")

        elif choice == "4":
            remove_raw_groups(email)
            print("\n[OK] All group access removed from raw groups export.")
            print("[NEXT] Run option 8 to recalculate risk.")

        elif choice == "5":
            remove_privileged_groups(email)
            print("[NEXT] Run option 8 to recalculate risk.")

        elif choice == "6":
            create_manual_review(email)

        elif choice == "7":
            generate_remediation_evidence(email)

        elif choice == "8":
            run_full_pipeline()

        elif choice == "9":
            break

        else:
            print("Invalid option.")


# ==================================================
# AI / EVIDENCE / DASHBOARD
# ==================================================

def launch_ai_advisor():
    run_command(
        "AI Governance Advisor",
        "python3 module_ollama_copilot/src/ollama_copilot.py"
    )


def launch_dashboard():
    subprocess.run("streamlit run app/trustshield_dashboard.py", shell=True, cwd=BASE_DIR)


def generate_evidence_only():
    run_command("Decision Engine", "python3 module_decision_engine/src/decision_engine.py")
    run_command("Evidence Vault", "python3 module_evidence_vault/src/evidence_vault.py")
    run_command("Quantum Integrity Vault", "python3 module_quantum_integrity/src/quantum_integrity_vault.py")
    run_command("Data Store Sync", "python3 module_data_store/src/data_store.py")


# ==================================================
# MAIN MENU
# ==================================================

def main_menu():
    while True:
        print("""
======================================
 TrustShield IAM AI
======================================
1. Analyze New Data
2. Identity Explorer
3. Investigate Identity
4. Find Problems
5. AI Governance Advisor
6. Generate Evidence
7. Launch Dashboard
8. Exit
======================================
""")

        choice = input("Select option: ").strip()

        if choice == "1":
            analyze_new_data_menu()

        elif choice == "2":
            identity_explorer_menu()

        elif choice == "3":
            investigate_identity()

        elif choice == "4":
            find_problems_menu()

        elif choice == "5":
            launch_ai_advisor()

        elif choice == "6":
            generate_evidence_only()

        elif choice == "7":
            launch_dashboard()

        elif choice == "8":
            print("Exiting TrustShield.")
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main_menu()
