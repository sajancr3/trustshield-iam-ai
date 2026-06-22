# TrustShield IAM AI - Identity Data Quality Report

Generated: 2026-06-09T15:43:09.932667Z

## Executive Summary

- Total Identities Reviewed: 17
- Identities With Issues: 11
- Critical Issues: 1
- High Issues: 15
- Average Data Quality Score: 75.0

## Identity Findings

### alice@corp.local
- Identity ID: 1002
- Data Quality Score: 75
- Confidence: Medium
- Issue Count: 1

#### High - privileged_user_without_mfa
- Field: mfa_enabled
- Description: Identity has privileged group membership but MFA is not enabled.
- Impact: Stolen credentials could provide elevated access without an additional verification factor.
- Recommendation: Enable MFA and enforce privileged access policy.

### david@corp.local
- Identity ID: 1003
- Data Quality Score: 40
- Confidence: Low
- Issue Count: 2

#### Critical - terminated_user_with_access
- Field: status/groups
- Description: Terminated identity still has group memberships.
- Impact: Leaver process may be incomplete, creating risk of unauthorized access.
- Recommendation: Remove all access and validate offboarding controls.

#### High - stale_identity_with_access
- Field: last_login_days
- Description: Identity has not logged in for 240 days but still has access.
- Impact: Dormant access increases the risk of unnoticed compromise or unnecessary entitlement exposure.
- Recommendation: Validate business need and remove access if no longer required.

### sarah@corp.local
- Identity ID: 1006
- Data Quality Score: 75
- Confidence: Medium
- Issue Count: 1

#### High - missing_manager
- Field: manager
- Description: Identity record has no manager or accountable owner.
- Impact: Access reviews and approvals may not have a valid business owner.
- Recommendation: Assign a manager or application owner for governance accountability.

### linda@corp.local
- Identity ID: 1008
- Data Quality Score: 75
- Confidence: Medium
- Issue Count: 1

#### High - missing_manager
- Field: manager
- Description: Identity record has no manager or accountable owner.
- Impact: Access reviews and approvals may not have a valid business owner.
- Recommendation: Assign a manager or application owner for governance accountability.

### bob@corp.local
- Identity ID: 1010
- Data Quality Score: 75
- Confidence: Medium
- Issue Count: 1

#### High - missing_manager
- Field: manager
- Description: Identity record has no manager or accountable owner.
- Impact: Access reviews and approvals may not have a valid business owner.
- Recommendation: Assign a manager or application owner for governance accountability.

### svc_sql@corp.local
- Identity ID: 1011
- Data Quality Score: 25
- Confidence: Very Low
- Issue Count: 3

#### High - missing_manager
- Field: manager
- Description: Identity record has no manager or accountable owner.
- Impact: Access reviews and approvals may not have a valid business owner.
- Recommendation: Assign a manager or application owner for governance accountability.

#### High - privileged_user_without_mfa
- Field: mfa_enabled
- Description: Identity has privileged group membership but MFA is not enabled.
- Impact: Stolen credentials could provide elevated access without an additional verification factor.
- Recommendation: Enable MFA and enforce privileged access policy.

#### High - stale_identity_with_access
- Field: last_login_days
- Description: Identity has not logged in for 365 days but still has access.
- Impact: Dormant access increases the risk of unnoticed compromise or unnecessary entitlement exposure.
- Recommendation: Validate business need and remove access if no longer required.

### svc_backup@corp.local
- Identity ID: 1012
- Data Quality Score: 50
- Confidence: Low
- Issue Count: 2

#### High - missing_manager
- Field: manager
- Description: Identity record has no manager or accountable owner.
- Impact: Access reviews and approvals may not have a valid business owner.
- Recommendation: Assign a manager or application owner for governance accountability.

#### High - stale_identity_with_access
- Field: last_login_days
- Description: Identity has not logged in for 300 days but still has access.
- Impact: Dormant access increases the risk of unnoticed compromise or unnecessary entitlement exposure.
- Recommendation: Validate business need and remove access if no longer required.

### contractor2@corp.local
- Identity ID: 1014
- Data Quality Score: 75
- Confidence: Medium
- Issue Count: 1

#### High - stale_identity_with_access
- Field: last_login_days
- Description: Identity has not logged in for 200 days but still has access.
- Impact: Dormant access increases the risk of unnoticed compromise or unnecessary entitlement exposure.
- Recommendation: Validate business need and remove access if no longer required.

### legacy@corp.local
- Identity ID: 1015
- Data Quality Score: 25
- Confidence: Very Low
- Issue Count: 3

#### High - missing_manager
- Field: manager
- Description: Identity record has no manager or accountable owner.
- Impact: Access reviews and approvals may not have a valid business owner.
- Recommendation: Assign a manager or application owner for governance accountability.

#### High - privileged_user_without_mfa
- Field: mfa_enabled
- Description: Identity has privileged group membership but MFA is not enabled.
- Impact: Stolen credentials could provide elevated access without an additional verification factor.
- Recommendation: Enable MFA and enforce privileged access policy.

#### High - stale_identity_with_access
- Field: last_login_days
- Description: Identity has not logged in for 400 days but still has access.
- Impact: Dormant access increases the risk of unnoticed compromise or unnecessary entitlement exposure.
- Recommendation: Validate business need and remove access if no longer required.

### Email: oracle_dba@corp.local
- Identity ID: Employee ID: 2001
- Data Quality Score: 85
- Confidence: Medium
- Issue Count: 1

#### Medium - invalid_last_login_value
- Field: last_login_days
- Description: Last login value is missing or not numeric.
- Impact: Staleness checks cannot be trusted for this identity.
- Recommendation: Fix source data format for last login information.

### oracle_dba@corp.local
- Identity ID: 2001
- Data Quality Score: 75
- Confidence: Medium
- Issue Count: 1

#### High - missing_manager
- Field: manager
- Description: Identity record has no manager or accountable owner.
- Impact: Access reviews and approvals may not have a valid business owner.
- Recommendation: Assign a manager or application owner for governance accountability.
