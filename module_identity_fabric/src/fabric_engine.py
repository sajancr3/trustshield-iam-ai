import pandas as pd
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

RAW = BASE_DIR / "raw"
NORMALIZED = BASE_DIR / "normalized"

NORMALIZED.mkdir(exist_ok=True)

hr = pd.read_csv(RAW / "hr_export.csv")
ad = pd.read_csv(RAW / "ad_export.csv")
groups = pd.read_csv(RAW / "groups_export.csv")

merged = hr.merge(
    ad,
    on="email",
    how="left"
)

group_map = (
    groups.groupby("email")["group_name"]
    .apply(list)
    .to_dict()
)

records = []

for _, row in merged.iterrows():

    identity = {
        "identity_id": row["employee_id"],
        "name": row["full_name"],
        "email": row["email"],
        "department": row["department"],
        "manager": (
            None
            if pd.isna(row["manager"])
            else row["manager"]
),
        "status": row["status"],
        "mfa_enabled": (
             False
             if pd.isna(row["mfa_enabled"])
             else row["mfa_enabled"]
),
        "last_login_days": (
                    999
                   if pd.isna(row["last_login_days"])
                  else row["last_login_days"]
),
        "groups": group_map.get(row["email"], [])
    }

    records.append(identity)

output = {
    "identities": records
}

with open(
    NORMALIZED / "identity_fabric.json",
    "w"
) as f:
    json.dump(output, f, indent=2)

print(
    f"Generated {len(records)} normalized identities"
)
