# M365 Identity Lifecycle Automation Lab

This portfolio lab models CSV-driven Microsoft Entra provisioning and an ordered Microsoft 365 offboarding workflow. The code emphasizes explicit approvals, `WhatIf`, per-action results, and honest partial-failure reporting.

> Live Microsoft Graph behavior has not been validated. The included identities, tenant values, logs, and test outcomes are fictional. Offline and mocked tests do not prove tenant permissions, licensing, retention, mailbox, OneDrive, session, or production behavior.

## Result model

Both scripts return structured action results with these states:

- `Planned`: policy or approval work remains.
- `SkippedWhatIf`: an approved path was previewed and no write occurred.
- `Completed`: the specific live/mock action returned successfully.
- `Failed`: the action failed with a known non-success result.
- `Unknown`: lookup, connection, or other indeterminate behavior requires investigation.

The workflow has no rollback. If a user is created and a later license action fails, the final status is failed and the completed user creation remains visible in the action list.

## Provisioning behavior

`Invoke-M365Provisioning.ps1` validates each CSV row, requires a two-letter ISO-style `UsageLocation`, checks for an exact existing UPN, creates a user, and evaluates the configured department-to-SKU mapping.

- A successful empty exact-filter query is treated as confirmed absence.
- Permission, connectivity, Graph, or ambiguous lookup failures stop creation.
- An existing user is a conflict. No reconciliation mode is implemented, so repeat runs are not described as automatically safe.
- Two-letter validation is only a format check; tenant and license policy still control whether the value is accepted.
- Temporary passwords use `RandomNumberGenerator`, require a change at next sign-in, and are displayed only after creation for approved secure delivery. They are not logged.

CSV columns: `FirstName`, `LastName`, `Department`, `Title`, `UsageLocation`, and optional `Manager`.

```powershell
.\Invoke-M365Provisioning.ps1 `
  -TenantId 'tenant-guid' -ClientId 'app-guid' `
  -CertificateThumbprint 'certificate-thumbprint' `
  -UPNDomain 'example.com' -CsvPath .\onboarding_queue.csv -WhatIf
```

## Offboarding behavior

`Invoke-M365Offboarding.ps1` is an ordered best-effort workflow with explicit partial-failure reporting. Its default is non-destructive: it may connect and resolve the user, but write actions remain `Planned`.

Separate approval switches control sign-in disablement and session revocation. License removal requires both `-ApproveLicenseRemoval` and `-LicensePrerequisitesConfirmed`.

```powershell
.\Invoke-M365Offboarding.ps1 `
  -UserPrincipalName 'user@example.com' `
  -TenantId 'tenant-guid' -ClientId 'app-guid' `
  -CertificateThumbprint 'certificate-thumbprint' -WhatIf `
  -ApproveDisableSignIn -ApproveSessionRevocation `
  -ApproveLicenseRemoval -LicensePrerequisitesConfirmed
```

Mailbox/data retention, ownership transfer, group cleanup, OneDrive/legal hold, and account deletion remain policy-dependent planned actions. They are not automatic defaults. Session revocation is a request whose effect must be verified; the script does not claim that all access tokens instantly terminate.

## Authentication

The top-level parameter set selects `ClientSecret` or `Certificate`, and that mode is passed explicitly into the nested connection helper. The helper does not infer the caller's parameter set from its own `$PSCmdlet.ParameterSetName`.

Application permissions and admin consent must be reviewed against the exact actions and least-privilege requirements of an authorized test tenant. Certificate authentication reduces client-secret handling but does not make the workflow production-ready by itself.

## Logs

Logs are editable local workflow records, not tamper-evident audit evidence. In `WhatIf`, they contain no `SUCCESS`, completed offboarding claim, session-revoked claim, or license-stripped claim.

## Verification

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse
Invoke-Pester .\tests
```

The tests cover explicit auth mode, planned versus completed states, `WhatIf` no-write behavior, invalid usage location, unknown lookup, existing-user conflict, partial license failure, approval absent/present, and failed final status. Graph cmdlets are mocked; no tenant connection is made by the test suite.

MIT licensed. See `LICENSE`.
