import sqlite3

DB_FILE = "trustshield.db"

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

print("""
========================================
 TrustShield AI Governance Advisor
========================================

Available Questions

- critical identities
- high risk users
- governance health
- mfa coverage
- pending reviews
- audit readiness
- top departments by risk
- terminated users with access

========================================
""")

question = input(
    "Ask a governance question: "
).lower().strip()

# --------------------------------------------------
# Critical Identities
# --------------------------------------------------

if "critical" in question:

    cursor.execute("""
    SELECT
        i.name,
        i.email,
        r.risk_score,
        r.severity,
        r.recommendation
    FROM risk_findings r
    JOIN identities i
    ON r.email = i.email
    WHERE r.severity='Critical'
    ORDER BY r.risk_score DESC
    """)

    rows = cursor.fetchall()

    print("\nCritical Identities\n")

    for row in rows:

        print(f"Name: {row[0]}")
        print(f"Email: {row[1]}")
        print(f"Risk Score: {row[2]}")
        print(f"Severity: {row[3]}")
        print(f"Recommendation: {row[4]}")
        print("-" * 40)

# --------------------------------------------------
# High Risk Users
# --------------------------------------------------

elif "high risk" in question:

    cursor.execute("""
    SELECT
        i.name,
        i.email,
        r.risk_score,
        r.severity
    FROM risk_findings r
    JOIN identities i
    ON r.email = i.email
    WHERE r.risk_score > 0
    ORDER BY r.risk_score DESC
    LIMIT 10
    """)

    rows = cursor.fetchall()

    print("\nHighest Risk Identities\n")

    for row in rows:

        print(
            f"{row[0]} | {row[1]} | "
            f"{row[3]} | Score={row[2]}"
        )

# --------------------------------------------------
# Governance Health
# --------------------------------------------------

elif "governance health" in question:

    cursor.execute("""
    SELECT COUNT(*)
    FROM risk_findings
    WHERE severity='Critical'
    """)

    critical = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM risk_findings
    WHERE severity='High'
    """)

    high = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM risk_findings
    WHERE severity='Medium'
    """)

    medium = cursor.fetchone()[0]

    score = max(
        0,
        100 - (critical * 15)
        - (high * 8)
        - (medium * 4)
    )

    print("\nGovernance Health Analysis\n")

    print(f"Governance Health: {score}/100")
    print(f"Critical Risks: {critical}")
    print(f"High Risks: {high}")
    print(f"Medium Risks: {medium}")

# --------------------------------------------------
# MFA Coverage
# --------------------------------------------------

elif "mfa" in question:

    cursor.execute("""
    SELECT COUNT(*)
    FROM identities
    """)

    total = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM identities
    WHERE mfa_enabled = 1
    """)

    enabled = cursor.fetchone()[0]

    coverage = round(
        (enabled / total) * 100,
        2
    ) if total else 0

    print("\nMFA Coverage Analysis\n")

    print(
        f"MFA Enabled: {enabled}/{total}"
    )

    print(
        f"Coverage: {coverage}%"
    )

    print("\nUsers WITHOUT MFA\n")

    cursor.execute("""
    SELECT
        name,
        email,
        department,
        status
    FROM identities
    WHERE mfa_enabled = 0
    ORDER BY department
    """)

    rows = cursor.fetchall()

    for row in rows:

        print(f"Name: {row[0]}")
        print(f"Email: {row[1]}")
        print(f"Department: {row[2]}")
        print(f"Status: {row[3]}")
        print("-" * 40)

# --------------------------------------------------
# Pending Reviews
# --------------------------------------------------

elif "pending review" in question:

    cursor.execute("""
    SELECT
        i.name,
        i.email,
        r.risk_score,
        r.severity
    FROM risk_findings r
    JOIN identities i
    ON r.email = i.email
    WHERE r.risk_score > 0
    ORDER BY r.risk_score DESC
    """)

    rows = cursor.fetchall()

    print("\nPending Reviews\n")

    for row in rows:

        print(
            f"{row[0]} | {row[1]} | "
            f"{row[3]} | Score={row[2]}"
        )

# --------------------------------------------------
# Audit Readiness
# --------------------------------------------------

elif "audit readiness" in question:

    cursor.execute("""
    SELECT COUNT(*)
    FROM risk_findings
    WHERE risk_score > 0
    """)

    risky = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM risk_findings
    WHERE severity='Critical'
    """)

    critical = cursor.fetchone()[0]

    readiness = max(
        0,
        100 - (critical * 10)
        - (risky * 3)
    )

    print("\nAudit Readiness\n")

    print(
        f"Audit Readiness Score: {readiness}%"
    )

    print(
        f"Risky Identities: {risky}"
    )

    print(
        f"Critical Findings: {critical}"
    )

# --------------------------------------------------
# Department Risk
# --------------------------------------------------

elif "department" in question:

    cursor.execute("""
    SELECT
        i.department,
        COUNT(*) as findings
    FROM risk_findings r
    JOIN identities i
    ON r.email = i.email
    WHERE r.risk_score > 0
    GROUP BY i.department
    ORDER BY findings DESC
    """)

    rows = cursor.fetchall()

    print("\nTop Departments By Risk\n")

    for row in rows:

        print(
            f"{row[0]} : {row[1]} risky identities"
        )

# --------------------------------------------------
# Terminated Users
# --------------------------------------------------

elif "terminated" in question:

    cursor.execute("""
    SELECT
        i.name,
        i.email,
        r.risk_score,
        r.severity
    FROM identities i
    JOIN risk_findings r
    ON i.email = r.email
    WHERE LOWER(i.status)='terminated'
    """)

    rows = cursor.fetchall()

    print("\nTerminated Users With Access Risk\n")

    for row in rows:

        print(f"Name: {row[0]}")
        print(f"Email: {row[1]}")
        print(f"Severity: {row[3]}")
        print(f"Risk Score: {row[2]}")
        print("-" * 40)

else:

    print(
        "\nQuestion not yet supported."
    )

conn.close()
