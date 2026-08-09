#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Zero-Touch M365 User Offboarding Engine — Disables an Entra ID account,
    revokes all active sign-in sessions, and strips all Office 365 licenses.

.DESCRIPTION
    Invoke-M365Offboarding.ps1 is a production-grade offboarding script for
    Microsoft 365 / Entra ID environments. It performs the following actions
    against a specified UserPrincipalName in a single, atomic sequence:

        1.  Connects to Microsoft Graph via certificate-based or client-secret auth.
        2.  Resolves the user object — aborts cleanly if the user does not exist.
        3.  Disables the account (AccountEnabled = $false) — immediate effect.
        4.  Revokes all active Azure AD sign-in sessions (Revoke-MgUserSignInSession).
             This invalidates all refresh tokens and terminates active SSO sessions.
        5.  Reads all currently assigned license SKUs.
        6.  Strips every license from the account in a single Graph API call.
        7.  Emits a timestamped, structured audit log for every action.

    The script is idempotent: re-running against an already-disabled, license-free
    account is safe and will log the no-op steps.

.PARAMETER UserPrincipalName
    The full UPN of the user to offboard (e.g., jane.smith@contoso.com). Required.

.PARAMETER TenantId
    The Azure AD Tenant ID (GUID). Required.

.PARAMETER ClientId
    The App Registration Client ID (GUID) for Graph API authentication. Required.

.PARAMETER ClientSecret
    [SecureString] The client secret for the App Registration. Mutually exclusive
    with -CertificateThumbprint. Prefer certificate auth in production.

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate installed in the local machine or current user
    certificate store. Preferred for production deployments.

.PARAMETER LogPath
    Path to the audit log file. Defaults to .\Logs\M365Offboarding_<timestamp>.log.

.PARAMETER WhatIf
    Simulates every step without making any changes to the tenant.

.EXAMPLE
    .\Invoke-M365Offboarding.ps1 `
        -UserPrincipalName "jane.smith@contoso.com" `
        -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientId  "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
        -CertificateThumbprint "AABBCCDDEEFF..."

.EXAMPLE
    .\Invoke-M365Offboarding.ps1 `
        -UserPrincipalName "tom.chen@contoso.com" `
        -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientId  "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
        -ClientSecret (Read-Host -AsSecureString "Enter Client Secret") `
        -WhatIf

.NOTES
    Author      : Zero-Touch IAM Engine
    Version     : 1.0.0
    Requires    : Microsoft.Graph (Install-Module Microsoft.Graph -Scope CurrentUser)
    Permissions : User.ReadWrite.All, Directory.ReadWrite.All (Application permissions)
    Impact      : Immediate — session revocation takes effect within seconds.
                  The user's access to all M365 services is terminated on completion.
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ClientSecret')]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ClientId,

    [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
    [ValidateNotNull()]
    [SecureString]$ClientSecret,

    [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
    [ValidateNotNullOrEmpty()]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = ".\Logs\M365Offboarding_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# REGION: LOGGING
# ---------------------------------------------------------------------------

function Write-AuditLog {
    <#
    .SYNOPSIS Writes a structured, timestamped entry to the audit log and console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Message,
        [Parameter(Mandatory)] [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')] [string]$Level,
        [Parameter()] [string]$UPN    = '',
        [Parameter()] [string]$Action = ''
    )

    $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $upnPart    = if ($UPN)    { " | UPN=$UPN" }       else { '' }
    $actionPart = if ($Action) { " | Action=$Action" } else { '' }
    $logLine    = "[$timestamp] [$Level]$upnPart$actionPart | $Message"

    $colour = switch ($Level) {
        'SUCCESS' { 'Green'  }
        'WARNING' { 'Yellow' }
        'ERROR'   { 'Red'    }
        default   { 'Cyan'   }
    }
    Write-Host $logLine -ForegroundColor $colour

    try {
        $logDir = Split-Path $LogPath -Parent
        if ($logDir -and -not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        Add-Content -Path $LogPath -Value $logLine -Encoding UTF8
    }
    catch {
        Write-Warning "Audit log write failed: $_"
    }
}

# ---------------------------------------------------------------------------
# REGION: GRAPH CONNECTION
# ---------------------------------------------------------------------------

function Connect-ToMicrosoftGraph {
    <#
    .SYNOPSIS Authenticates to Microsoft Graph using the supplied credential method.
    #>
    [CmdletBinding()]
    param()

    Write-AuditLog -Level 'INFO' -Action 'GraphConnect' -Message "Initiating Microsoft Graph connection (TenantId=$TenantId, ClientId=$ClientId, AuthMethod=$($PSCmdlet.ParameterSetName))"

    if ($WhatIfPreference) {
        Write-AuditLog -Level 'WARNING' -Action 'GraphConnect' -Message 'WhatIf mode — skipping actual Graph connection.'
        return
    }

    $connectParams = @{
        TenantId  = $TenantId
        ClientId  = $ClientId
        NoWelcome = $true
    }

    if ($PSCmdlet.ParameterSetName -eq 'Certificate') {
        $connectParams['CertificateThumbprint'] = $CertificateThumbprint
    }
    else {
        $connectParams['ClientSecretCredential'] = [System.Net.NetworkCredential]::new(
            '', $ClientSecret
        ).Password | ForEach-Object {
            [System.Management.Automation.PSCredential]::new($ClientId,
                (ConvertTo-SecureString $_ -AsPlainText -Force))
        }
    }

    try {
        Connect-MgGraph @connectParams -ErrorAction Stop
        Write-AuditLog -Level 'SUCCESS' -Action 'GraphConnect' -Message 'Connected to Microsoft Graph successfully.'
    }
    catch {
        Write-AuditLog -Level 'ERROR' -Action 'GraphConnect' -Message "Graph connection failed: $_"
        throw
    }
}

# ---------------------------------------------------------------------------
# REGION: OFFBOARDING STEPS
# ---------------------------------------------------------------------------

function Resolve-TargetUser {
    <#
    .SYNOPSIS Retrieves the Entra ID user object. Throws if not found.
    #>
    [CmdletBinding()]
    [OutputType([Microsoft.Graph.PowerShell.Models.MicrosoftGraphUser])]
    param()

    Write-AuditLog -Level 'INFO' -Action 'ResolveUser' -UPN $UserPrincipalName -Message 'Looking up user in Entra ID...'

    if ($WhatIfPreference) {
        Write-AuditLog -Level 'WARNING' -Action 'ResolveUser' -UPN $UserPrincipalName -Message 'WhatIf: Skipping live lookup. Returning synthetic object.'
        # Return a mock object for downstream WhatIf steps
        return [PSCustomObject]@{
            Id                = '00000000-0000-0000-0000-000000000000'
            UserPrincipalName = $UserPrincipalName
            DisplayName       = 'WhatIf User'
            AccountEnabled    = $true
            AssignedLicenses  = @()
        }
    }

    try {
        $user = Get-MgUser -UserId $UserPrincipalName `
            -Property 'Id,UserPrincipalName,DisplayName,AccountEnabled,AssignedLicenses' `
            -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -match '404|Request_ResourceNotFound|does not exist') {
            Write-AuditLog -Level 'ERROR' -Action 'ResolveUser' -UPN $UserPrincipalName -Message 'User not found in Entra ID. Offboarding aborted.'
        }
        else {
            Write-AuditLog -Level 'ERROR' -Action 'ResolveUser' -UPN $UserPrincipalName -Message "Unexpected error during user lookup: $_"
        }
        throw
    }

    Write-AuditLog -Level 'SUCCESS' -Action 'ResolveUser' -UPN $UserPrincipalName -Message "User resolved. ObjectId=$($user.Id) | DisplayName='$($user.DisplayName)' | AccountEnabled=$($user.AccountEnabled)"
    return $user
}

function Disable-EntraAccount {
    <#
    .SYNOPSIS Sets AccountEnabled = $false on the target user. Idempotent.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$UserId,
        [Parameter(Mandatory)] [bool]$CurrentState
    )

    if (-not $CurrentState) {
        Write-AuditLog -Level 'INFO' -Action 'DisableAccount' -UPN $UserPrincipalName -Message 'Account is already disabled — no change required.'
        return
    }

    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, 'Disable Entra ID Account (AccountEnabled = $false)')) {
        Write-AuditLog -Level 'WARNING' -Action 'DisableAccount' -UPN $UserPrincipalName -Message 'WhatIf: Account disable skipped.'
        return
    }

    try {
        Update-MgUser -UserId $UserId -AccountEnabled $false -ErrorAction Stop
        Write-AuditLog -Level 'SUCCESS' -Action 'DisableAccount' -UPN $UserPrincipalName -Message 'Account disabled successfully (AccountEnabled = $false).'
    }
    catch {
        Write-AuditLog -Level 'ERROR' -Action 'DisableAccount' -UPN $UserPrincipalName -Message "Failed to disable account: $_"
        throw
    }
}

function Invoke-SessionRevocation {
    <#
    .SYNOPSIS
        Calls Revoke-MgUserSignInSession, which invalidates all refresh tokens
        and forces re-authentication for every active session and app.
        Effect is near-immediate (typically < 60 seconds for Azure services).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$UserId
    )

    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, 'Revoke all active Azure AD sign-in sessions')) {
        Write-AuditLog -Level 'WARNING' -Action 'RevokeSession' -UPN $UserPrincipalName -Message 'WhatIf: Session revocation skipped.'
        return
    }

    try {
        $result = Invoke-MgInvalidateUserRefreshToken -UserId $UserId -ErrorAction Stop

        if ($result) {
            Write-AuditLog -Level 'SUCCESS' -Action 'RevokeSession' -UPN $UserPrincipalName -Message 'All refresh tokens invalidated. Active SSO sessions terminated.'
        }
        else {
            # Graph returns a boolean; a $false result is unusual but non-fatal
            Write-AuditLog -Level 'WARNING' -Action 'RevokeSession' -UPN $UserPrincipalName -Message 'Revocation call returned false — tenant may require delay. Verify via Entra ID Sign-In Logs.'
        }
    }
    catch {
        # If the newer cmdlet isn't available, fall back to the v1 endpoint
        if ($_.Exception.Message -match 'not found|not recognized') {
            Write-AuditLog -Level 'WARNING' -Action 'RevokeSession' -UPN $UserPrincipalName -Message "Invoke-MgInvalidateUserRefreshToken not available — trying Revoke-MgUserSignInSession fallback."
            try {
                Revoke-MgUserSignInSession -UserId $UserId -ErrorAction Stop | Out-Null
                Write-AuditLog -Level 'SUCCESS' -Action 'RevokeSession' -UPN $UserPrincipalName -Message 'Sign-in sessions revoked via fallback cmdlet.'
            }
            catch {
                Write-AuditLog -Level 'ERROR' -Action 'RevokeSession' -UPN $UserPrincipalName -Message "Fallback session revocation failed: $_"
                throw
            }
        }
        else {
            Write-AuditLog -Level 'ERROR' -Action 'RevokeSession' -UPN $UserPrincipalName -Message "Session revocation failed: $_"
            throw
        }
    }
}

function Remove-AllLicenses {
    <#
    .SYNOPSIS
        Reads all assigned license SKUs and removes them in a single Graph call.
        If the account has no licenses, logs a no-op and returns cleanly.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$UserId,
        [Parameter(Mandatory)] [object[]]$AssignedLicenses
    )

    $skuIds = @($AssignedLicenses | Where-Object { $_.SkuId } | Select-Object -ExpandProperty SkuId)

    if ($skuIds.Count -eq 0) {
        Write-AuditLog -Level 'INFO' -Action 'RemoveLicenses' -UPN $UserPrincipalName -Message 'No licenses assigned — nothing to remove.'
        return
    }

    $skuList = $skuIds -join ', '
    Write-AuditLog -Level 'INFO' -Action 'RemoveLicenses' -UPN $UserPrincipalName -Message "Found $($skuIds.Count) assigned license(s): $skuList"

    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, "Remove $($skuIds.Count) license(s): $skuList")) {
        Write-AuditLog -Level 'WARNING' -Action 'RemoveLicenses' -UPN $UserPrincipalName -Message 'WhatIf: License removal skipped.'
        return
    }

    try {
        Set-MgUserLicense -UserId $UserId `
            -AddLicenses @() `
            -RemoveLicenses $skuIds `
            -ErrorAction Stop | Out-Null

        Write-AuditLog -Level 'SUCCESS' -Action 'RemoveLicenses' -UPN $UserPrincipalName -Message "All $($skuIds.Count) license(s) removed successfully. SKUs: $skuList"
    }
    catch {
        Write-AuditLog -Level 'ERROR' -Action 'RemoveLicenses' -UPN $UserPrincipalName -Message "License removal failed: $_"
        throw
    }
}

# ---------------------------------------------------------------------------
# REGION: MAIN EXECUTION
# ---------------------------------------------------------------------------

function Invoke-Offboarding {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-AuditLog -Level 'INFO' -Action 'Startup' -Message "=== Invoke-M365Offboarding.ps1 started. Mode=$(if($WhatIfPreference){'WHATIF'}else{'LIVE'}) ==="
    Write-AuditLog -Level 'INFO' -Action 'Startup' -Message "Target UPN: $UserPrincipalName"
    Write-AuditLog -Level 'INFO' -Action 'Startup' -Message "Log file: $LogPath"

    # Step 1: Connect
    Connect-ToMicrosoftGraph

    # Step 2: Resolve user — fatal if not found
    $user = Resolve-TargetUser

    # Step 3: Disable account — immediate
    Disable-EntraAccount -UserId $user.Id -CurrentState $user.AccountEnabled

    # Step 4: Revoke all sign-in sessions — terminates active tokens
    Invoke-SessionRevocation -UserId $user.Id

    # Step 5: Strip all licenses
    Remove-AllLicenses -UserId $user.Id -AssignedLicenses $user.AssignedLicenses

    # Summary
    Write-AuditLog -Level 'SUCCESS' -Action 'Offboarding' -UPN $UserPrincipalName -Message '=== Offboarding sequence complete. Account disabled | Sessions revoked | Licenses stripped. ==='
    Write-AuditLog -Level 'WARNING' -Action 'PostOffboard' -UPN $UserPrincipalName -Message 'Recommended next steps: Remove from security groups, forward mailbox, revoke MFA methods, archive data per retention policy.'

    if (-not $WhatIfPreference) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
        Write-AuditLog -Level 'INFO' -Action 'Cleanup' -Message 'Disconnected from Microsoft Graph.'
    }
}

# Entry point
Invoke-Offboarding
