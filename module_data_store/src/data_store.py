import json
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

DB_FILE = BASE_DIR / "trustshield.db"

IDENTITY_FILE = (
    BASE_DIR
    / "module_identity_fabric"
    / "normalized"
    / "identity_fabric.json"
)

RISK_FILE = (
    BASE_DIR
    / "module_identity_risk"
    / "reports"
    / "identity_risk_report.json"
)

conn = sqlite3.connect(DB_FILE)
cur = conn.cursor()

# -------------------------
# Tables
# -------------------------

cur.execute("""
CREATE TABLE IF NOT EXISTS identities (
    identity_id TEXT PRIMARY KEY,
    name TEXT,
    email TEXT,
    department TEXT,
    manager TEXT,
    status TEXT,
    mfa_enabled BOOLEAN,
    last_login_days INTEGER
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS risk_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id INTEGER,
    email TEXT,
    severity TEXT,
    risk_score INTEGER,
    recommendation TEXT
)
""")

# -------------------------
# Clear old data
# -------------------------

cur.execute("DELETE FROM identities")
cur.execute("DELETE FROM risk_findings")

# -------------------------
# Load identities
# -------------------------

with open(IDENTITY_FILE, "r") as f:
    identities = json.load(f)

for identity in identities["identities"]:

    cur.execute("""
    INSERT INTO identities
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        identity["identity_id"],
        identity["name"],
        identity["email"],
        identity["department"],
        identity["manager"],
        identity["status"],
        identity["mfa_enabled"],
        identity["last_login_days"]
    ))

# -------------------------
# Load risks
# -------------------------

with open(RISK_FILE, "r") as f:
    risks = json.load(f)

for risk in risks["identity_risks"]:

    cur.execute("""
    INSERT INTO risk_findings
    (
        identity_id,
        email,
        severity,
        risk_score,
        recommendation
    )
    VALUES (?, ?, ?, ?, ?)
    """, (
        risk["identity_id"],
        risk["email"],
        risk["severity"],
        risk["risk_score"],
        risk["recommended_action"]
    ))

conn.commit()

print(
    f"[+] SQLite Database Created: {DB_FILE}"
)

print(
    f"[+] Identities Loaded: {len(identities['identities'])}"
)

print(
    f"[+] Risk Findings Loaded: {len(risks['identity_risks'])}"
)

conn.close()
