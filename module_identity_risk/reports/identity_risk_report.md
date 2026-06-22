# TrustShield IAM AI - Identity Risk Report

Generated: 2026-06-09T15:43:09.945896Z

## Executive Summary

- Total Identities Reviewed: 17
- Risky Identities: 7
- Critical: 2
- High: 1
- Medium: 2
- Low: 2

## Risk Findings

### svc_sql@corp.local
- Name: Service SQL
- Identity ID: 1011
- Severity: Critical
- Risk Score: 100
- Department: IT
- Manager: None
- Recommended Action: Immediate remediation required. Disable or restrict access, validate ownership, enforce MFA, and create audit evidence.

#### Risk Signals

- **Privileged access without MFA** (Authentication Risk, +30)
  - Explanation: Identity has privileged access but MFA is not enabled.
  - Evidence: `{"mfa_enabled": false, "privileged_groups": ["Database Admins"]}`
- **Dormant privileged identity** (Dormant Access Risk, +35)
  - Explanation: Identity has not logged in for 365 days but still has privileged access.
  - Evidence: `{"last_login_days": 365, "privileged_groups": ["Database Admins"]}`
- **Privileged identity without accountable owner** (Ownership Risk, +25)
  - Explanation: Privileged identity has no manager or accountable business owner.
  - Evidence: `{"manager": null, "privileged_groups": ["Database Admins"]}`
- **Stale access still assigned** (Access Hygiene Risk, +20)
  - Explanation: Identity has not logged in for 365 days but still has assigned access.
  - Evidence: `{"last_login_days": 365, "groups": ["Database Admins"]}`
- **Low identity data confidence** (Data Quality Risk, +15)
  - Explanation: Identity has low data quality confidence, which can weaken access review and audit decisions.
  - Evidence: `{"data_quality_score": 25, "confidence": "Very Low", "issue_count": 3}`

### legacy@corp.local
- Name: Legacy Admin
- Identity ID: 1015
- Severity: Critical
- Risk Score: 100
- Department: IT
- Manager: None
- Recommended Action: Immediate remediation required. Disable or restrict access, validate ownership, enforce MFA, and create audit evidence.

#### Risk Signals

- **Privileged access without MFA** (Authentication Risk, +30)
  - Explanation: Identity has privileged access but MFA is not enabled.
  - Evidence: `{"mfa_enabled": false, "privileged_groups": ["Domain Admins", "Database Admins"]}`
- **Dormant privileged identity** (Dormant Access Risk, +35)
  - Explanation: Identity has not logged in for 400 days but still has privileged access.
  - Evidence: `{"last_login_days": 400, "privileged_groups": ["Domain Admins", "Database Admins"]}`
- **Excessive critical privilege concentration** (Least Privilege Risk, +25)
  - Explanation: Identity belongs to multiple critical privileged groups.
  - Evidence: `{"critical_groups": ["Domain Admins", "Database Admins"]}`
- **Privileged identity without accountable owner** (Ownership Risk, +25)
  - Explanation: Privileged identity has no manager or accountable business owner.
  - Evidence: `{"manager": null, "privileged_groups": ["Domain Admins", "Database Admins"]}`
- **Stale access still assigned** (Access Hygiene Risk, +20)
  - Explanation: Identity has not logged in for 400 days but still has assigned access.
  - Evidence: `{"last_login_days": 400, "groups": ["Domain Admins", "Database Admins"]}`
- **Low identity data confidence** (Data Quality Risk, +15)
  - Explanation: Identity has low data quality confidence, which can weaken access review and audit decisions.
  - Evidence: `{"data_quality_score": 25, "confidence": "Very Low", "issue_count": 3}`

### david@corp.local
- Name: David Lee
- Identity ID: 1003
- Severity: High
- Risk Score: 75
- Department: IT
- Manager: bob@corp.local
- Recommended Action: Remove access immediately and validate leaver control completion.

#### Risk Signals

- **Terminated identity still has access** (Lifecycle Risk, +40)
  - Explanation: HR status shows terminated, but the identity still has group memberships.
  - Evidence: `{"status": "terminated", "groups": ["IT Users"]}`
- **Stale access still assigned** (Access Hygiene Risk, +20)
  - Explanation: Identity has not logged in for 240 days but still has assigned access.
  - Evidence: `{"last_login_days": 240, "groups": ["IT Users"]}`
- **Low identity data confidence** (Data Quality Risk, +15)
  - Explanation: Identity has low data quality confidence, which can weaken access review and audit decisions.
  - Evidence: `{"data_quality_score": 40, "confidence": "Low", "issue_count": 2}`

### alice@corp.local
- Name: Alice Brown
- Identity ID: 1002
- Severity: Medium
- Risk Score: 65
- Department: Finance
- Manager: crsajan98@gmail.com
- Recommended Action: Enable MFA and review privileged group membership.

#### Risk Signals

- **Privileged access without MFA** (Authentication Risk, +30)
  - Explanation: Identity has privileged access but MFA is not enabled.
  - Evidence: `{"mfa_enabled": false, "privileged_groups": ["Finance Admins", "Domain Admins"]}`
- **Dormant privileged identity** (Dormant Access Risk, +35)
  - Explanation: Identity has not logged in for 180 days but still has privileged access.
  - Evidence: `{"last_login_days": 180, "privileged_groups": ["Finance Admins", "Domain Admins"]}`

### contractor2@corp.local
- Name: Contractor Two
- Identity ID: 1014
- Severity: Medium
- Risk Score: 55
- Department: Payments
- Manager: maria@corp.local
- Recommended Action: Review during the next access certification campaign.

#### Risk Signals

- **Dormant privileged identity** (Dormant Access Risk, +35)
  - Explanation: Identity has not logged in for 200 days but still has privileged access.
  - Evidence: `{"last_login_days": 200, "privileged_groups": ["Payment Operators"]}`
- **Stale access still assigned** (Access Hygiene Risk, +20)
  - Explanation: Identity has not logged in for 200 days but still has assigned access.
  - Evidence: `{"last_login_days": 200, "groups": ["Payment Operators"]}`

### svc_backup@corp.local
- Name: Service Backup
- Identity ID: 1012
- Severity: Low
- Risk Score: 35
- Department: IT
- Manager: None
- Recommended Action: No urgent action required. Continue monitoring.

#### Risk Signals

- **Stale access still assigned** (Access Hygiene Risk, +20)
  - Explanation: Identity has not logged in for 300 days but still has assigned access.
  - Evidence: `{"last_login_days": 300, "groups": ["Backup Operators"]}`
- **Low identity data confidence** (Data Quality Risk, +15)
  - Explanation: Identity has low data quality confidence, which can weaken access review and audit decisions.
  - Evidence: `{"data_quality_score": 50, "confidence": "Low", "issue_count": 2}`

### sarah@corp.local
- Name: Sarah Wilson
- Identity ID: 1006
- Severity: Low
- Risk Score: 25
- Department: Security
- Manager: None
- Recommended Action: No urgent action required. Continue monitoring.

#### Risk Signals

- **Privileged identity without accountable owner** (Ownership Risk, +25)
  - Explanation: Privileged identity has no manager or accountable business owner.
  - Evidence: `{"manager": null, "privileged_groups": ["Security Admins", "Domain Admins"]}`
