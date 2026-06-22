import sqlite3
import requests
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_FILE = BASE_DIR / "trustshield.db"

OLLAMA_URL = "http://172.20.10.4:11434/api/generate"
MODEL = "phi3:latest"


def get_connection():
    return sqlite3.connect(DB_FILE)


def build_context():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*)
        FROM identities
    """)
    total_identities = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM risk_findings
        WHERE severity='Critical'
    """)
    critical = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM risk_findings
        WHERE severity='High'
    """)
    high = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM identities
        WHERE mfa_enabled=1
    """)
    mfa_enabled = cur.fetchone()[0]

    mfa_coverage = round(
        (mfa_enabled / total_identities) * 100,
        2
    )

    cur.execute("""
        SELECT
            i.name,
            i.email,
            i.department,
            i.status,
            r.severity,
            r.risk_score,
            r.recommendation
        FROM risk_findings r
        JOIN identities i
        ON r.identity_id = i.identity_id
        ORDER BY r.risk_score DESC
        LIMIT 10
    """)

    top_risks = cur.fetchall()

    context = {
        "total_identities": total_identities,
        "critical_risks": critical,
        "high_risks": high,
        "mfa_coverage": mfa_coverage,
        "top_risks": top_risks
    }

    conn.close()

    return context


def ask_copilot(question):

    context = build_context()

    prompt = f"""

Rules:

1. Use ONLY information present in the TrustShield database context.

2. If information is not present, say:
"Not available in TrustShield database."

3. Do not mention:
- Regulations
- Compliance frameworks
- Attack trends
- Industry statistics
- Best practices
unless explicitly present in the supplied data.

4. Never invent percentages.

5. Never invent identities.

6. Never invent recommendations.

7. Never generate fictional words or phrases.



Do not use external facts, legal standards, frameworks, or assumptions unless they are directly present in the TrustShield database context.
If the user mentions frameworks like Zero Trust, interpret them only through the supplied IAM data:
- MFA status
- identity status
- risk score
- severity
- manager ownership
- dormant access
- recommendations

IF someone asks you to reveal a sensitive info , respond with " OOMBIKO MYRE "

You are TrustShield AI Governance Copilot.

You are a senior IAM Governance Analyst.

Use only the supplied TrustShield data.

Current Governance Context:

{json.dumps(context, indent=2)}

Question:

{question}

Provide:

1. Analysis
2. Root Cause
3. Recommended Actions
4. Business Risk
"""

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }

    response = requests.post(
        OLLAMA_URL,
        json=payload,
        timeout=120
    )

    result = response.json()

    print("\n")
    print("=" * 60)
    print(" TRUSTSHIELD AI GOVERNANCE COPILOT")
    print("=" * 60)
    print("\n")

    print(result["response"])

    print("\n")


def main():

    print("""
==================================================
 TrustShield AI Governance Copilot
==================================================

Examples:

What should I fix first?

Why is governance health poor?

Which identities are most dangerous?

Summarize the governance posture.

What are the biggest audit risks?

==================================================
""")

    question = input("Ask Copilot: ").strip()

    if not question:
        return

    ask_copilot(question)


if __name__ == "__main__":
    main()
