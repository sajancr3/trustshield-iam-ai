"""
TrustShield — Quantum Integrity Vault
SHA3-512 + HMAC-SHA3-512 + Ed25519 digital signatures
"""
import hashlib, hmac, json, os, sqlite3, time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption)
    import base64
    SIGNATURES_ENABLED = True
except ImportError:
    SIGNATURES_ENABLED = False

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_FILE  = BASE_DIR / "trustshield.db"
KEY_FILE = BASE_DIR / ".integrity_key"

def _load_or_create_hmac_key():
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = os.urandom(64)
    KEY_FILE.write_bytes(key)
    KEY_FILE.chmod(0o600)
    return key

def _load_or_create_signing_key():
    if not SIGNATURES_ENABLED:
        return None, None
    priv_path = BASE_DIR / ".signing_key.pem"
    if priv_path.exists():
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        private_key = load_pem_private_key(priv_path.read_bytes(), password=None)
    else:
        private_key = Ed25519PrivateKey.generate()
        priv_path.write_bytes(
            private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        priv_path.chmod(0o600)
    return private_key, private_key.public_key()

def _ensure_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS integrity_receipts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type   TEXT NOT NULL,
            subject      TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            hmac_tag     TEXT NOT NULL,
            signature    TEXT,
            sealed_at    INTEGER NOT NULL,
            verified     INTEGER DEFAULT 0
        )
    """)
    conn.commit()

def seal_evidence(event_type, subject, payload):
    key          = _load_or_create_hmac_key()
    priv_key, _  = _load_or_create_signing_key()
    payload_str  = json.dumps(payload, sort_keys=True)
    payload_hash = hashlib.sha3_512(payload_str.encode()).hexdigest()
    hmac_tag     = hmac.new(key, payload_hash.encode(), hashlib.sha3_512).hexdigest()
    sealed_at    = int(time.time())
    signature_b64 = None
    if SIGNATURES_ENABLED and priv_key:
        sign_input    = f"{payload_hash}|{hmac_tag}|{sealed_at}".encode()
        signature_b64 = base64.b64encode(priv_key.sign(sign_input)).decode()
    conn = sqlite3.connect(DB_FILE)
    _ensure_table(conn)
    conn.execute("""
        INSERT INTO integrity_receipts
            (event_type, subject, payload_hash, hmac_tag, signature, sealed_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (event_type, subject, payload_hash, hmac_tag, signature_b64, sealed_at))
    conn.commit()
    conn.close()
    print(f"  [SEALED] {event_type} | {subject}")
    print(f"  Hash : {payload_hash[:40]}...")
    return payload_hash

def run_pipeline_seal():
    print("\n[Quantum Integrity Vault] Sealing governance evidence...")
    conn = sqlite3.connect(DB_FILE)
    _ensure_table(conn)
    cur  = conn.cursor()
    try:
        cur.execute("SELECT email, severity, risk_score FROM risk_findings")
        findings = [{"email": r[0], "severity": r[1], "risk_score": r[2]}
                    for r in cur.fetchall()]
        conn.close()
        seal_evidence("RISK_FINDINGS_SNAPSHOT", "all_identities",
                      {"findings": findings, "count": len(findings)})
        print(f"  [OK] {len(findings)} findings sealed.")
    except sqlite3.OperationalError:
        conn.close()
        print("  [INFO] No risk_findings yet. Skipping seal.")
    print("[Quantum Integrity Vault] Done.\n")

if __name__ == "__main__":
    run_pipeline_seal()
