#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Zero-Touch M365 User Provisioning Engine — Reads from a CSV queue,
    creates Entra ID (Azure AD) users, assigns licenses, and emits an audit log.

.DESCRIPTION
    Invoke-M365Provisioning.ps1 is a production-grade provisioning script designed
    for Microsoft 365 / Entra ID environments. It performs the following actions
    for each row in the onboarding_queue.csv:

        1. Connects to Microsoft Graph via certificate-based or client-secret auth.
        2. Validates the row schema and skips malformed entries with a log warning.
        3. Generates a cryptographically random, policy-compliant temporary password.
        4. Creates the Entra ID user with ForceChangePasswordNextSignIn = $true.
        5. Conditionally assigns an Office 365 license based on the Department field.
        6. Writes a timestamped audit entry for every action (success or failure).

    License SKU mapping (Department → SkuPartNumber):
        Engineering / IT Support  → ENTERPRISEPREMIUM  (Microsoft 365 E5)
        Finance / Human Resources → ENTERPRISEPACK      (Office 365 E3)
        Marketing / Default       → O365_BUSINESS_PREMIUM (Microsoft 365 Business Premium)

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

.PARAMETER CsvPath
    Path to the onboarding queue CSV. Defaults to .\onboarding_queue.csv.

.PARAMETER UPNDomain
    The verified domain suffix to append to generated UPNs (e.g., "contoso.com").
    Required.

.PARAMETER LogPath
    Path to the audit log file. Defaults to .\Logs\M365Provisioning_<timestamp>.log.

.PARAMETER WhatIf
    Runs the full script in simulation mode — no users are created, no licenses
    are assigned, and no Graph API write calls are made.

.EXAMPLE
    .\Invoke-M365Provisioning.ps1 `
        -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientId  "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
        -CertificateThumbprint "AABBCCDDEEFF..." `
        -UPNDomain "contoso.com"

.EXAMPLE
    .\Invoke-M365Provisioning.ps1 `
        -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientId  "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
        -ClientSecret (Read-Host -AsSecureString "Enter Client Secret") `
        -UPNDomain "contoso.com" `
        -WhatIf

.NOTES
    Author      : Zero-Touch IAM Engine
    Version     : 1.0.0
    Requires    : Microsoft.Graph (Install-Module Microsoft.Graph -Scope CurrentUser)
    Permissions : User.ReadWrite.All, Directory.ReadWrite.All,
                  Organization.Read.All (Application permissions in Entra ID)
    CSV Schema  : FirstName, LastName, Department, Title, UsageLocation, Manager
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ClientSecret')]
param(
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

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$UPNDomain,

    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath = ".\onboarding_queue.csv",

    [Parameter(Mandatory = $false)]
    [string]$LogPath = ".\Logs\M365Provisioning_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# REGION: CONSTANTS
# ---------------------------------------------------------------------------

# Mapping of Department name → M365 License SKU Part Number
# Update SkuId GUIDs to match your tenant (run: Get-MgSubscribedSku)
$script:LicenseMap = @{
    'Engineering'     = @{ SkuPartNumber = 'ENTERPRISEPREMIUM';       SkuId = $null }
    'IT Support'      = @{ SkuPartNumber = 'ENTERPRISEPREMIUM';       SkuId = $null }
    'Finance'         = @{ SkuPartNumber = 'ENTERPRISEPACK';          SkuId = $null }
    'Human Resources' = @{ SkuPartNumber = 'ENTERPRISEPACK';          SkuId = $null }
    'Marketing'       = @{ SkuPartNumber = 'O365_BUSINESS_PREMIUM';   SkuId = $null }
    'Default'         = @{ SkuPartNumber = 'O365_BUSINESS_PREMIUM';   SkuId = $null }
}

$script:RequiredCsvColumns = @('FirstName', 'LastName', 'Department', 'Title', 'UsageLocation')

$script:GraphScopes = @(
    'User.ReadWrite.All',
    'Directory.ReadWrite.All',
    'Organization.Read.All'
)

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
        [Parameter()] [string]$UPN = '',
        [Parameter()] [string]$Action = ''
    )

    $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $upnPart    = if ($UPN)    { " | UPN=$UPN" }    else { '' }
    $actionPart = if ($Action) { " | Action=$Action" } else { '' }
    $logLine    = "[$timestamp] [$Level]$upnPart$actionPart | $Message"

    # Console output with colour
    $colour = switch ($Level) {
        'SUCCESS' { 'Green'  }
        'WARNING' { 'Yellow' }
        'ERROR'   { 'Red'    }
        default   { 'Cyan'   }
    }
    Write-Host $logLine -ForegroundColor $colour

    # File output
    try {
        $logDir = Split-Path $script:LogPath -Parent
        if ($logDir -and -not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        Add-Content -Path $script:LogPath -Value $logLine -Encoding UTF8
    }
    catch {
        Write-Warning "Audit log write failed: $_"
    }
}

# ---------------------------------------------------------------------------
# REGION: PASSWORD GENERATION
# ---------------------------------------------------------------------------

function New-ComplexPassword {
    <#
    .SYNOPSIS
        Generates a cryptographically random, policy-compliant temporary password.
        Meets Entra ID defaults: 8+ chars, upper, lower, digit, special.
    #>
    [OutputType([string])]
    param(
        [int]$Length = 16
    )

    $upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ'      # no I/O to avoid visual confusion
    $lower   = 'abcdefghjkmnpqrstuvwxyz'        # no i/l/o
    $digits  = '23456789'                        # no 0/1
    $special = '!@#$%^&*()-_=+'
    $all     = $upper + $lower + $digits + $special

    $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = [byte[]]::new($Length * 2)
    $rng.GetBytes($bytes)

    $chars = [System.Collections.Generic.List[char]]::new()

    # Guarantee at least one of each required class
    $chars.Add($upper[ $bytes[0] % $upper.Length ])
    $chars.Add($lower[ $bytes[1] % $lower.Length ])
    $chars.Add($digits[$bytes[2] % $digits.Length])
    $chars.Add($special[$bytes[3] % $special.Length])

    # Fill remaining length from the full pool
    for ($i = 4; $i -lt $Length; $i++) {
        $chars.Add($all[$bytes[$i] % $all.Length])
    }

    # Fisher-Yates shuffle using RNG
    $shuffleBytes = [byte[]]::new($chars.Count)
    $rng.GetBytes($shuffleBytes)
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = $shuffleBytes[$i] % ($i + 1)
        $tmp       = $chars[$i]
        $chars[$i] = $chars[$j]
        $chars[$j] = $tmp
    }

    $rng.Dispose()
    return -join $chars
}

# ---------------------------------------------------------------------------
# REGION: GRAPH HELPERS
# ---------------------------------------------------------------------------

function Connect-ToMicrosoftGraph {
    <#
    .SYNOPSIS Authenticates to Microsoft Graph using the supplied credential method.
    #>
    [CmdletBinding()]
    param()

    Write-AuditLog -Level 'INFO' -Action 'GraphConnect' -Message "Initiating Microsoft Graph connection (TenantId=$TenantId, ClientId=$ClientId, AuthMethod=$($PSCmdlet.ParameterSetName))"

    $connectParams = @{
        TenantId = $TenantId
        ClientId = $ClientId
        NoWelcome = $true
    }

    if ($PSCmdlet.ParameterSetName -eq 'Certificate') {
        $connectParams['CertificateThumbprint'] = $CertificateThumbprint
    }
    else {
        # Convert SecureString → plain text only within the call; never stored in a variable
        $connectParams['ClientSecretCredential'] = [System.Net.NetworkCredential]::new(
            '', $ClientSecret
        ).Password | ForEach-Object {
            [System.Management.Automation.PSCredential]::new($ClientId,
                (ConvertTo-SecureString $_ -AsPlainText -Force))
        }
    }

    if ($PSBoundParameters.ContainsKey('WhatIf')) {
        Write-AuditLog -Level 'WARNING' -Action 'GraphConnect' -Message 'WhatIf mode — skipping actual Graph connection.'
        return
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

function Resolve-LicenseSkuIds {
    <#
    .SYNOPSIS
        Queries the tenant's subscribed SKUs and populates the SkuId field
        in $script:LicenseMap. Called once after authentication.
    #>
    [CmdletBinding()]
    param()

    Write-AuditLog -Level 'INFO' -Action 'ResolveSKUs' -Message 'Fetching subscribed SKUs from tenant...'

    if ($PSBoundParameters.ContainsKey('WhatIf')) {
        Write-AuditLog -Level 'WARNING' -Action 'ResolveSKUs' -Message 'WhatIf mode — SKU resolution skipped.'
        return
    }

    try {
        $subscribedSkus = Get-MgSubscribedSku -All -ErrorAction Stop

        foreach ($key in @($script:LicenseMap.Keys)) {
            $skuPartNumber = $script:LicenseMap[$key].SkuPartNumber
            $matched = $subscribedSkus | Where-Object { $_.SkuPartNumber -eq $skuPartNumber } | Select-Object -First 1

            if ($matched) {
                $script:LicenseMap[$key].SkuId = $matched.SkuId
                Write-AuditLog -Level 'INFO' -Action 'ResolveSKUs' -Message "Mapped '$skuPartNumber' → SkuId=$($matched.SkuId) (Available: $($matched.PrepaidUnits.Enabled - $matched.ConsumedUnits))"
            }
            else {
                Write-AuditLog -Level 'WARNING' -Action 'ResolveSKUs' -Message "SKU '$skuPartNumber' not found in tenant subscriptions. Users in '$key' will not receive a license."
            }
        }
    }
    catch {
        Write-AuditLog -Level 'ERROR' -Action 'ResolveSKUs' -Message "Failed to resolve SKUs: $_"
        throw
    }
}

function Get-LicenseAssignment {
    <#
    .SYNOPSIS Returns a license assignment hashtable for the given department, or $null if no SKU resolved.
    #>
    param([string]$Department)

    $entry = if ($script:LicenseMap.ContainsKey($Department)) {
        $script:LicenseMap[$Department]
    }
    else {
        $script:LicenseMap['Default']
    }

    if (-not $entry.SkuId) { return $null }

    return @{
        SkuId           = $entry.SkuId
        DisabledPlans   = @()   # Assign all plans; narrow here if needed
    }
}

function New-EntraUser {
    <#
    .SYNOPSIS Creates a single Entra ID user from a CSV row object.
    .OUTPUTS Returns $true on success, $false on failure.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [PSCustomObject]$Row,
        [Parameter(Mandatory)] [string]$TempPassword
    )

    $upn         = "$($Row.FirstName.ToLower()).$($Row.LastName.ToLower())@$UPNDomain"
    $displayName = "$($Row.FirstName) $($Row.LastName)"
    $mailNick    = "$($Row.FirstName.ToLower())$($Row.LastName.ToLower())"

    Write-AuditLog -Level 'INFO' -Action 'CreateUser' -UPN $upn -Message "Preparing to create user: DisplayName='$displayName', Department='$($Row.Department)', Title='$($Row.Title)'"

    # --- WhatIf guard ---
    if (-not $PSCmdlet.ShouldProcess($upn, 'Create Entra ID User')) {
        Write-AuditLog -Level 'WARNING' -Action 'CreateUser' -UPN $upn -Message 'WhatIf: User creation skipped.'
        return $true
    }

    # --- Check for pre-existing user ---
    try {
        $existingUser = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction Stop
        if ($existingUser) {
            Write-AuditLog -Level 'WARNING' -Action 'CreateUser' -UPN $upn -Message "User already exists (ObjectId=$($existingUser.Id)). Skipping creation."
            return $false
        }
    }
    catch {
        # A 404 / empty result is expected; any other error should surface
        if ($_.Exception.Message -notmatch '404|not found|does not exist') {
            Write-AuditLog -Level 'ERROR' -Action 'CreateUser' -UPN $upn -Message "Pre-existence check failed: $_"
            return $false
        }
    }

    # --- Build user body ---
    $passwordProfile = @{
        Password                      = $TempPassword
        ForceChangePasswordNextSignIn = $true
    }

    $userParams = @{
        DisplayName       = $displayName
        GivenName         = $Row.FirstName
        Surname           = $Row.LastName
        UserPrincipalName = $upn
        MailNickname      = $mailNick
        Department        = $Row.Department
        JobTitle          = $Row.Title
        UsageLocation     = if ($Row.UsageLocation) { $Row.UsageLocation } else { 'US' }
        AccountEnabled    = $true
        PasswordProfile   = $passwordProfile
    }

    # Optionally set manager (best-effort; non-fatal if manager UPN not found)
    $managerRef = $null
    if ($Row.Manager -and $Row.Manager -ne '') {
        try {
            $mgr = Get-MgUser -Filter "userPrincipalName eq '$($Row.Manager)'" -ErrorAction Stop
            if ($mgr) { $managerRef = $mgr.Id }
        }
        catch {
            Write-AuditLog -Level 'WARNING' -Action 'SetManager' -UPN $upn -Message "Manager '$($Row.Manager)' not found — skipping manager assignment."
        }
    }

    # --- Create user ---
    try {
        $newUser = New-MgUser -BodyParameter $userParams -ErrorAction Stop
        Write-AuditLog -Level 'SUCCESS' -Action 'CreateUser' -UPN $upn -Message "User created. ObjectId=$($newUser.Id)"
    }
    catch {
        Write-AuditLog -Level 'ERROR' -Action 'CreateUser' -UPN $upn -Message "User creation failed: $_"
        return $false
    }

    # --- Set manager (best-effort) ---
    if ($managerRef) {
        try {
            $managerBody = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$managerRef" }
            Set-MgUserManagerByRef -UserId $newUser.Id -BodyParameter $managerBody -ErrorAction Stop
            Write-AuditLog -Level 'INFO' -Action 'SetManager' -UPN $upn -Message "Manager set to ObjectId=$managerRef"
        }
        catch {
            Write-AuditLog -Level 'WARNING' -Action 'SetManager' -UPN $upn -Message "Manager assignment failed (non-fatal): $_"
        }
    }

    # --- Assign license ---
    $licenseAssignment = Get-LicenseAssignment -Department $Row.Department

    if ($licenseAssignment) {
        try {
            Set-MgUserLicense -UserId $newUser.Id `
                -AddLicenses @($licenseAssignment) `
                -RemoveLicenses @() `
                -ErrorAction Stop

            Write-AuditLog -Level 'SUCCESS' -Action 'AssignLicense' -UPN $upn `
                -Message "License assigned: SkuId=$($licenseAssignment.SkuId) (Dept='$($Row.Department)')"
        }
        catch {
            Write-AuditLog -Level 'ERROR' -Action 'AssignLicense' -UPN $upn -Message "License assignment failed: $_"
            # User was created; this is a non-fatal error — still return true
        }
    }
    else {
        Write-AuditLog -Level 'WARNING' -Action 'AssignLicense' -UPN $upn -Message "No resolvable SKU for department '$($Row.Department)'. License not assigned."
    }

    Write-AuditLog -Level 'SUCCESS' -Action 'Provisioning' -UPN $upn -Message "Provisioning complete."

    # -----------------------------------------------------------------------
    # SECURE CREDENTIAL DELIVERY
    # The temporary password is generated in memory and never written to disk.
    # It must be transmitted to the user via an approved secure channel (e.g., 
    # self-destructing message, password manager, or direct verbal exchange).
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host "  ========================================================" -ForegroundColor DarkCyan
    Write-Host "  NEW USER CREDENTIAL GENERATED" -ForegroundColor Cyan
    Write-Host "  UPN      : $upn" -ForegroundColor White
    Write-Host "  Password : $TempPassword" -ForegroundColor Yellow
    Write-Host "  ACTION   : Transmit these details via an approved secure channel." -ForegroundColor Red
    Write-Host "  ========================================================" -ForegroundColor DarkCyan
    Write-Host ""

    Write-AuditLog -Level 'INFO' -Action 'Security' -UPN $upn -Message "Temporary password generated in memory and displayed to technician. Transmit via secure channel. Not written to disk."

    return $true
}

function Test-CsvRow {
    <#
    .SYNOPSIS Validates a CSV row has all required columns populated. Returns $true if valid.
    #>
    param([PSCustomObject]$Row, [int]$RowIndex)

    foreach ($col in $script:RequiredCsvColumns) {
        if (-not ($Row.PSObject.Properties.Name -contains $col) -or
            [string]::IsNullOrWhiteSpace($Row.$col)) {
            Write-AuditLog -Level 'WARNING' -Action 'Validation' -Message "Row $RowIndex skipped — missing or empty required field: '$col'."
            return $false
        }
    }
    return $true
}

# ---------------------------------------------------------------------------
# REGION: MAIN EXECUTION
# ---------------------------------------------------------------------------

function Invoke-Provisioning {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-AuditLog -Level 'INFO' -Action 'Startup' -Message "=== Invoke-M365Provisioning.ps1 started. Mode=$(if($WhatIfPreference){'WHATIF'}else{'LIVE'}) ==="
    Write-AuditLog -Level 'INFO' -Action 'Startup' -Message "Log file: $($script:LogPath)"

    # --- Load CSV ---
    Write-AuditLog -Level 'INFO' -Action 'LoadCSV' -Message "Loading onboarding queue from: $CsvPath"
    try {
        $queue = Import-Csv -Path $CsvPath -ErrorAction Stop
    }
    catch {
        Write-AuditLog -Level 'ERROR' -Action 'LoadCSV' -Message "Failed to import CSV '$CsvPath': $_"
        throw
    }

    if ($queue.Count -eq 0) {
        Write-AuditLog -Level 'WARNING' -Action 'LoadCSV' -Message 'CSV is empty. Nothing to provision.'
        return
    }

    Write-AuditLog -Level 'INFO' -Action 'LoadCSV' -Message "Loaded $($queue.Count) row(s) from CSV."

    # --- Authenticate ---
    Connect-ToMicrosoftGraph

    # --- Resolve license SKU IDs from tenant ---
    Resolve-LicenseSkuIds

    # --- Process each row ---
    $stats = @{ Total = $queue.Count; Success = 0; Skipped = 0; Failed = 0 }

    for ($i = 0; $i -lt $queue.Count; $i++) {
        $row      = $queue[$i]
        $rowIndex = $i + 1

        Write-AuditLog -Level 'INFO' -Action 'ProcessRow' -Message "--- Processing row $rowIndex of $($queue.Count) ---"

        if (-not (Test-CsvRow -Row $row -RowIndex $rowIndex)) {
            $stats.Skipped++
            continue
        }

        $tempPw = New-ComplexPassword -Length 16
        $result = New-EntraUser -Row $row -TempPassword $tempPw

        if ($result) { $stats.Success++ }
        else         { $stats.Failed++  }
    }

    # --- Summary ---
    Write-AuditLog -Level 'INFO' -Action 'Summary' -Message "=== Provisioning run complete ==="
    Write-AuditLog -Level 'INFO' -Action 'Summary' -Message "Total: $($stats.Total) | Success: $($stats.Success) | Skipped: $($stats.Skipped) | Failed: $($stats.Failed)"

    if (-not $PSBoundParameters.ContainsKey('WhatIf')) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
        Write-AuditLog -Level 'INFO' -Action 'Cleanup' -Message 'Disconnected from Microsoft Graph.'
    }
}

# Entry point
Invoke-Provisioning
