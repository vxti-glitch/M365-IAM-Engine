#Requires -Version 5.1

<#
.SYNOPSIS
    Plans or runs an ordered Microsoft 365 offboarding workflow.

.DESCRIPTION
    The default is non-destructive. Each policy-dependent action is recorded as
    Planned until its explicit approval switch and prerequisites are supplied.
    The result lists Planned, SkippedWhatIf, Completed, Failed, or Unknown for
    every action. There is no rollback and partial completion is reported.

.PARAMETER ApproveDisableSignIn
    Explicit approval to set AccountEnabled to false.

.PARAMETER ApproveSessionRevocation
    Explicit approval to request sign-in session revocation.

.PARAMETER ApproveLicenseRemoval
    Explicit approval to remove assigned licenses. Also requires
    -LicensePrerequisitesConfirmed.

.PARAMETER LicensePrerequisitesConfirmed
    Confirms that retention, mailbox/data ownership, legal hold, and other
    organization-specific prerequisites were reviewed before license removal.

.NOTES
    Offline WhatIf tests do not validate live Microsoft Graph behavior.
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ClientSecret')]
param(
    [Parameter(Mandatory, Position = 0)][ValidateNotNullOrEmpty()][string]$UserPrincipalName,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TenantId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ClientId,
    [Parameter(Mandatory, ParameterSetName = 'ClientSecret')][ValidateNotNull()][SecureString]$ClientSecret,
    [Parameter(Mandatory, ParameterSetName = 'Certificate')][ValidateNotNullOrEmpty()][string]$CertificateThumbprint,
    [string]$LogPath = ".\Logs\M365Offboarding_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",
    [switch]$ApproveDisableSignIn,
    [switch]$ApproveSessionRevocation,
    [switch]$ApproveLicenseRemoval,
    [switch]$LicensePrerequisitesConfirmed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$authMethod = $PSCmdlet.ParameterSetName
$results = [System.Collections.Generic.List[object]]::new()

function Write-WorkflowLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR')][string]$Level = 'INFO',
        [string]$Action = ''
    )
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] | UPN=$UserPrincipalName | Action=$Action | $Message"
    Write-Host $line
    $directory = Split-Path $LogPath -Parent
    if ($directory -and -not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force -WhatIf:$false | Out-Null
    }
    Add-Content -LiteralPath $LogPath -Value $line -Encoding utf8 -WhatIf:$false
}

function Add-ActionResult {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][ValidateSet('Planned', 'SkippedWhatIf', 'Completed', 'Failed', 'Unknown')][string]$State,
        [Parameter(Mandatory)][string]$Detail,
        [bool]$Required = $false
    )
    $result = [pscustomobject]@{
        Action = $Action
        State = $State
        Required = $Required
        Detail = $Detail
    }
    $results.Add($result)
    $level = if ($State -in @('Failed', 'Unknown')) { 'ERROR' } elseif ($State -in @('Planned', 'SkippedWhatIf')) { 'WARNING' } else { 'INFO' }
    Write-WorkflowLog -Action $Action -Level $level -Message "State=$State; $Detail"
    return $result
}

function Test-GraphNotFound {
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    return $ErrorRecord.Exception.Message -match '404|Request_ResourceNotFound|does not exist'
}

function Connect-WorkflowGraph {
    param([Parameter(Mandatory)][ValidateSet('ClientSecret', 'Certificate')][string]$AuthMethod)
    if ($WhatIfPreference) {
        Add-ActionResult -Action 'GraphConnect' -State 'SkippedWhatIf' -Detail "No connection attempted; AuthMethod=$AuthMethod" | Out-Null
        return $true
    }
    try {
        $connect = @{ TenantId = $TenantId; ClientId = $ClientId; NoWelcome = $true }
        if ($AuthMethod -eq 'Certificate') {
            $connect.CertificateThumbprint = $CertificateThumbprint
        }
        else {
            $connect.ClientSecretCredential = [pscredential]::new($ClientId, $ClientSecret)
        }
        Connect-MgGraph @connect -ErrorAction Stop
        Add-ActionResult -Action 'GraphConnect' -State 'Completed' -Detail "Connected using AuthMethod=$AuthMethod" | Out-Null
        return $true
    }
    catch {
        Add-ActionResult -Action 'GraphConnect' -State 'Unknown' -Required $true -Detail "Connection failed: $($_.Exception.Message)" | Out-Null
        return $false
    }
}

function Resolve-WorkflowUser {
    if ($WhatIfPreference) {
        Add-ActionResult -Action 'ResolveUser' -State 'SkippedWhatIf' -Detail 'No live lookup attempted; downstream actions remain previews.' | Out-Null
        return [pscustomobject]@{ Id = 'whatif-user'; AccountEnabled = $true; AssignedLicenses = @([pscustomobject]@{ SkuId = 'whatif-sku' }) }
    }
    try {
        $user = Get-MgUser -UserId $UserPrincipalName -Property 'Id,AccountEnabled,AssignedLicenses' -ErrorAction Stop
        if ($null -eq $user -or @($user).Count -ne 1) {
            Add-ActionResult -Action 'ResolveUser' -State 'Unknown' -Required $true -Detail 'Lookup returned zero or multiple records.' | Out-Null
            return $null
        }
        Add-ActionResult -Action 'ResolveUser' -State 'Completed' -Detail "Resolved ObjectId=$($user.Id)" | Out-Null
        return $user
    }
    catch {
        if (Test-GraphNotFound -ErrorRecord $_) {
            Add-ActionResult -Action 'ResolveUser' -State 'Failed' -Required $true -Detail 'User was not found; no writes attempted.' | Out-Null
        }
        else {
            Add-ActionResult -Action 'ResolveUser' -State 'Unknown' -Required $true -Detail "Lookup failed; no writes attempted: $($_.Exception.Message)" | Out-Null
        }
        return $null
    }
}

function Invoke-ApprovedAction {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][bool]$Approved,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Operation,
        [bool]$Required = $false
    )
    if (-not $Approved) {
        Add-ActionResult -Action $Action -State 'Planned' -Required $Required -Detail "Approval required: $Description" | Out-Null
        return
    }
    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, $Description)) {
        Add-ActionResult -Action $Action -State 'SkippedWhatIf' -Required $Required -Detail "Approved path previewed; no write performed: $Description" | Out-Null
        return
    }
    try {
        & $Operation
        Add-ActionResult -Action $Action -State 'Completed' -Required $Required -Detail $Description | Out-Null
    }
    catch {
        Add-ActionResult -Action $Action -State 'Failed' -Required $Required -Detail "$Description failed: $($_.Exception.Message)" | Out-Null
    }
}

function Invoke-OffboardingWorkflow {
    Write-WorkflowLog -Action 'Startup' -Message "Ordered best-effort workflow started; AuthMethod=$authMethod; Mode=$(if ($WhatIfPreference) { 'WhatIf' } else { 'Live' })"
    if (-not (Connect-WorkflowGraph -AuthMethod $authMethod)) { return }
    $user = Resolve-WorkflowUser
    if ($null -eq $user) { return }

    Invoke-ApprovedAction -Action 'DisableSignIn' -Approved $ApproveDisableSignIn.IsPresent `
        -Description 'Disable sign-in by setting AccountEnabled=false' -Required $true `
        -Operation { Update-MgUser -UserId $user.Id -AccountEnabled $false -ErrorAction Stop }

    Invoke-ApprovedAction -Action 'RevokeSessions' -Approved $ApproveSessionRevocation.IsPresent `
        -Description 'Request sign-in session revocation; verify effect separately' `
        -Operation { Revoke-MgUserSignInSession -UserId $user.Id -ErrorAction Stop | Out-Null }

    $licenseApproved = $ApproveLicenseRemoval -and $LicensePrerequisitesConfirmed
    $licenseDescription = if ($ApproveLicenseRemoval -and -not $LicensePrerequisitesConfirmed) {
        'License approval supplied but retention/ownership/legal-hold prerequisites are not confirmed'
    } else { 'Remove currently assigned license SKU IDs after prerequisite review' }
    $licenseIds = @()
    foreach ($assignedLicense in @($user.AssignedLicenses)) {
        if ($assignedLicense.SkuId) { $licenseIds += $assignedLicense.SkuId }
    }
    Invoke-ApprovedAction -Action 'RemoveLicenses' -Approved $licenseApproved `
        -Description $licenseDescription `
        -Operation {
            if ($licenseIds.Count -gt 0) {
                Set-MgUserLicense -UserId $user.Id -AddLicenses @() -RemoveLicenses $licenseIds -ErrorAction Stop | Out-Null
            }
        }

    foreach ($pending in @(
        'MailboxAndRetentionPolicy', 'OwnershipTransfer', 'GroupCleanup',
        'OneDriveAndLegalHold', 'AccountDeletion'
    )) {
        Add-ActionResult -Action $pending -State 'Planned' -Detail 'Policy-dependent action is intentionally not implemented as an automatic default.' | Out-Null
    }
}

try {
    Invoke-OffboardingWorkflow
}
finally {
    if (-not $WhatIfPreference) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
}

$failedRequired = @($results | Where-Object { $_.Required -and $_.State -in @('Failed', 'Unknown') })
$completed = @($results | Where-Object State -eq 'Completed').Count
$planned = @($results | Where-Object State -in @('Planned', 'SkippedWhatIf')).Count
$final = [pscustomobject]@{
    UserPrincipalName = $UserPrincipalName
    Status = if ($failedRequired.Count -gt 0) { 'Failed' } elseif ($completed -gt 0) { 'PartialOrCompleted' } else { 'PlannedOnly' }
    Succeeded = ($failedRequired.Count -eq 0)
    CompletedCount = $completed
    PlannedCount = $planned
    Results = @($results)
    RollbackAvailable = $false
}

Write-WorkflowLog -Action 'Summary' -Level $(if ($final.Succeeded) { 'INFO' } else { 'ERROR' }) `
    -Message "FinalStatus=$($final.Status); Completed=$completed; PlannedOrSkipped=$planned; FailedRequired=$($failedRequired.Count); RollbackAvailable=false"
$final
if (-not $final.Succeeded) { throw 'Offboarding workflow ended with a failed or unknown required action.' }
