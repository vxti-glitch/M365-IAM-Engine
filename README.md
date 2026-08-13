# M365 Zero-Touch Provisioning and Offboarding Engine

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square&logo=powershell&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-API%20v1.0-0078D4?style=flat-square&logo=microsoft&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Microsoft%20365%20%7C%20Entra%20ID-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Auth](https://img.shields.io/badge/Auth-Certificate%20%7C%20Client%20Secret-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)

A production-grade Identity and Access Management (IAM) automation suite for Microsoft 365 and Entra ID. Two PowerShell scripts, backed by the Microsoft Graph API, automate the full user lifecycle from provisioning through offboarding — eliminating manual IT intervention and reducing the attack surface created by orphaned accounts and stale sessions.

---

## Table of Contents

- [Business Value](#business-value)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [How to Use](#how-to-use)
  - [Provisioning](#1-provisioning)
  - [Offboarding](#2-offboarding)
- [CSV Schema](#csv-schema)
- [License SKU Mapping](#license-sku-mapping)
- [Audit Logging](#audit-logging)
- [Security Notes](#security-notes)

---

## Business Value

Manual user provisioning and offboarding are among the highest-volume, lowest-value tasks in an IT department. They are also among the most consequential when delayed or executed incorrectly.

**Provisioning cost without automation:**

A single manual onboarding — creating an account, assigning a license, setting a password, notifying the user — takes an average of 15–30 minutes of IT labor per user. At 100 hires per year in a mid-size organization, that is 25–50 hours of technician time spent on a repeatable, deterministic task.

**Offboarding risk without automation:**

The average time to disable a departed employee's account is 4–7 hours in organizations without automated offboarding, according to industry benchmarks. During that window, the account remains active with valid refresh tokens — a credential exposure that represents a direct insider threat and organizational security risk.

**What this engine delivers:**

| Metric | Manual Process | Automated (This Engine) |
|---|---|---|
| Provisioning time per user | 15–30 minutes | Under 60 seconds |
| Offboarding time to disable + revoke | 4–7 hours | Under 30 seconds |
| License assignment accuracy | Dependent on technician | Policy-enforced, deterministic |
| Audit trail | Manual ticket notes | Structured, timestamped log file |
| Password compliance | Inconsistent | Cryptographically generated, policy-enforced |

---

## Architecture

```
M365-IAM-Engine/
├── Invoke-M365Provisioning.ps1   # Bulk user creation engine
├── Invoke-M365Offboarding.ps1    # Single-user termination engine
└── onboarding_queue.csv          # Input queue for provisioning
```

**Authentication flow:**

Both scripts authenticate to Microsoft Graph using an Entra ID App Registration with Application-level permissions. Two credential methods are supported:

- **Certificate (recommended for production):** No secret stored on disk. Uses a certificate thumbprint resolved from the local certificate store.
- **Client Secret:** Accepted as a `SecureString` parameter at runtime. The plaintext value is never assigned to a variable and is not logged.

**Graph API calls made:**

| Script | Graph Operation |
|---|---|
| Provisioning | `POST /users`, `PUT /users/{id}/manager/$ref`, `POST /users/{id}/assignLicense` |
| Offboarding | `PATCH /users/{id}` (disable), `POST /users/{id}/invalidateAllRefreshTokens`, `POST /users/{id}/assignLicense` (remove) |

---

## Prerequisites

**PowerShell module:**

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

**Entra ID App Registration — required Application permissions (admin-consented):**

| Permission | Used By |
|---|---|
| `User.ReadWrite.All` | Create, update, disable users |
| `Directory.ReadWrite.All` | Assign manager, read directory |
| `Organization.Read.All` | Read subscribed SKUs for license mapping |

---

## Configuration

No configuration file is required. All parameters are passed at runtime via named parameters. See `-WhatIf` mode for safe testing prior to production execution.

---

## How to Use

### 1. Provisioning

**Reads** `onboarding_queue.csv`, creates each user in Entra ID, assigns a cryptographically generated temporary password with `ForceChangePasswordNextSignIn = $true`, and assigns an Office 365 license based on the user's department.

**Certificate authentication (recommended):**

```powershell
.\Invoke-M365Provisioning.ps1 `
    -TenantId             "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ClientId             "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
    -CertificateThumbprint "AABBCCDDEEFF00112233445566778899AABBCCDD" `
    -UPNDomain            "contoso.com" `
    -CsvPath              ".\onboarding_queue.csv"
```

**Client secret authentication:**

```powershell
.\Invoke-M365Provisioning.ps1 `
    -TenantId      "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ClientId      "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
    -ClientSecret  (Read-Host -AsSecureString "Enter Client Secret") `
    -UPNDomain     "contoso.com"
```

**Simulation mode (no changes written to tenant):**

```powershell
.\Invoke-M365Provisioning.ps1 -TenantId "..." -ClientId "..." -CertificateThumbprint "..." -UPNDomain "contoso.com" -WhatIf
```

---

### 2. Offboarding

**Takes a single `UserPrincipalName`** and executes the following sequence atomically:

1. Disables the account (`AccountEnabled = $false`) — effective immediately
2. Revokes all active Azure AD refresh tokens — terminates all active SSO sessions
3. Removes all assigned Office 365 licenses in a single API call

```powershell
.\Invoke-M365Offboarding.ps1 `
    -UserPrincipalName    "jane.smith@contoso.com" `
    -TenantId             "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ClientId             "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
    -CertificateThumbprint "AABBCCDDEEFF00112233445566778899AABBCCDD"
```

**Simulation mode:**

```powershell
.\Invoke-M365Offboarding.ps1 -UserPrincipalName "jane.smith@contoso.com" -TenantId "..." -ClientId "..." -CertificateThumbprint "..." -WhatIf
```

Both scripts are **idempotent** — re-execution against an already-processed user is safe and produces no duplicate actions.

---

## CSV Schema

`onboarding_queue.csv` — required columns:

| Column | Required | Description |
|---|---|---|
| `FirstName` | Yes | User's given name |
| `LastName` | Yes | User's surname |
| `Department` | Yes | Determines license tier (see mapping below) |
| `Title` | Yes | Job title |
| `UsageLocation` | Yes | ISO 3166-1 alpha-2 country code (e.g., `US`) |
| `Manager` | No | Full UPN of the user's manager |

Rows with missing required fields are skipped and logged as `WARNING` entries. The remaining rows continue to process.

---

## License SKU Mapping

License assignment is determined at runtime by reading the tenant's active subscriptions via `Get-MgSubscribedSku`. The department-to-SKU mapping is:

| Department | SKU Part Number | License |
|---|---|---|
| Engineering, IT Support | `ENTERPRISEPREMIUM` | Microsoft 365 E5 |
| Finance, Human Resources | `ENTERPRISEPACK` | Office 365 E3 |
| Marketing, (default) | `O365_BUSINESS_PREMIUM` | Microsoft 365 Business Premium |

If a SKU is not available in the tenant's subscriptions, the user is created without a license and the event is logged as a `WARNING`.

---

## Audit Logging

Both scripts write structured, timestamped log entries to `.\Logs\` on each execution. Format:

```
[2026-08-08 19:51:03] [SUCCESS] | UPN=jane.smith@contoso.com | Action=CreateUser | User created. ObjectId=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
[2026-08-08 19:51:04] [SUCCESS] | UPN=jane.smith@contoso.com | Action=AssignLicense | License assigned: SkuId=06ebc4ee-1bb5-47dd-8120-11324bc54e06 (Dept='Finance')
```

**Provisioning** outputs generated temporary passwords only to the console for the executing technician. These are generated securely in-memory, never written to disk or audit logs, and must be transmitted via an approved secure channel.

Log levels: `INFO`, `SUCCESS`, `WARNING`, `ERROR`

---

## Security Notes

- Temporary passwords are generated using `System.Security.Cryptography.RandomNumberGenerator`. `Get-Random` is not used.
- Temporary passwords are kept in-memory and never written to disk or logs. They must be distributed via an approved secure channel.
- Client secrets are accepted only as `[SecureString]` and converted to plaintext in-memory only at the point of the API call. They are not stored in variables or written to logs.
- Certificate-based authentication is the recommended auth method for production deployments — it removes the need to manage or rotate a client secret.
- The offboarding script calls `Invoke-MgInvalidateUserRefreshToken` (with a fallback to `Revoke-MgUserSignInSession`), which invalidates all issued refresh tokens. Active access tokens remain valid for their remaining TTL (typically up to 1 hour). For immediate hard termination, configure Continuous Access Evaluation (CAE) in Entra ID.

---

## License

MIT
