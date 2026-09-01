#Requires -Version 5.1

<#
.SYNOPSIS
    Runs a CSV-driven Microsoft Entra provisioning workflow with explicit results.

.DESCRIPTION
    Each row is validated and returns per-action states: Planned,
    SkippedWhatIf, Completed, Failed, or Unknown. Existing users are conflicts;
    this script does not claim reconciliation or blanket repeat-run safety.
    There is no rollback. A created user followed by a license failure is
    reported as partial failure.

.NOTES
    Offline WhatIf and mock tests do not validate live Microsoft Graph behavior.
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ClientSecret')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TenantId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ClientId,
    [Parameter(Mandatory, ParameterSetName = 'ClientSecret')][ValidateNotNull()][SecureString]$ClientSecret,
    [Parameter(Mandatory, ParameterSetName = 'Certificate')][ValidateNotNullOrEmpty()][string]$CertificateThumbprint,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$UPNDomain,
    [ValidateScript({ Test-Path $_ -PathType Leaf })][string]$CsvPath = '.\onboarding_queue.csv',
    [string]$LogPath = ".\Logs\M365Provisioning_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",
    [switch]$SuppressCredentialDisplay
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$authMethod = $PSCmdlet.ParameterSetName
$results = [System.Collections.Generic.List[object]]::new()
$requiredColumns = @('FirstName', 'LastName', 'Department', 'Title', 'UsageLocation')
$licensePartNumbers = @{
    'Engineering' = 'ENTERPRISEPREMIUM'; 'IT Support' = 'ENTERPRISEPREMIUM'
    'Finance' = 'ENTERPRISEPACK'; 'Human Resources' = 'ENTERPRISEPACK'
    'Marketing' = 'O365_BUSINESS_PREMIUM'; 'Default' = 'O365_BUSINESS_PREMIUM'
}

function Write-WorkflowLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR')][string]$Level = 'INFO',
        [string]$Action = '', [string]$UPN = ''
    )
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] | UPN=$UPN | Action=$Action | $Message"
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
        [string]$UPN = '', [bool]$Required = $false
    )
    $item = [pscustomobject]@{ Action = $Action; State = $State; Required = $Required; UPN = $UPN; Detail = $Detail }
    $results.Add($item)
    $level = if ($State -in @('Failed', 'Unknown')) { 'ERROR' } elseif ($State -in @('Planned', 'SkippedWhatIf')) { 'WARNING' } else { 'INFO' }
    Write-WorkflowLog -Level $level -Action $Action -UPN $UPN -Message "State=$State; $Detail"
    return $item
}

function New-ComplexPassword {
    [OutputType([string])]
    param([ValidateRange(12, 128)][int]$Length = 16)
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghjkmnpqrstuvwxyz', '23456789', '!@#$%^&*()-_=+')
    $pool = $sets -join ''
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $chars = [Collections.Generic.List[char]]::new()
        foreach ($set in $sets) {
            $bytes = [byte[]]::new(4); $rng.GetBytes($bytes)
            $chars.Add($set[[BitConverter]::ToUInt32($bytes, 0) % $set.Length])
        }
        while ($chars.Count -lt $Length) {
            $bytes = [byte[]]::new(4); $rng.GetBytes($bytes)
            $chars.Add($pool[[BitConverter]::ToUInt32($bytes, 0) % $pool.Length])
        }
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $bytes = [byte[]]::new(4); $rng.GetBytes($bytes)
            $j = [BitConverter]::ToUInt32($bytes, 0) % ($i + 1)
            $temp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $temp
        }
        return -join $chars
    }
    finally { $rng.Dispose() }
}

function ConvertTo-MailToken {
    param([Parameter(Mandatory)][string]$Value)
    $token = ($Value.Trim().ToLowerInvariant() -replace '\s+', '.' -replace '[^a-z0-9._-]', '').Trim('.-_')
    if ([string]::IsNullOrWhiteSpace($token)) { throw "Cannot build mail token from '$Value'." }
    return $token
}

function Connect-WorkflowGraph {
    param([Parameter(Mandatory)][ValidateSet('ClientSecret', 'Certificate')][string]$AuthMethod)
    if ($WhatIfPreference) {
        Add-ActionResult -Action 'GraphConnect' -State 'SkippedWhatIf' -Detail "No connection attempted; AuthMethod=$AuthMethod" | Out-Null
        return $true
    }
    try {
        $connect = @{ TenantId = $TenantId; ClientId = $ClientId; NoWelcome = $true }
        if ($AuthMethod -eq 'Certificate') { $connect.CertificateThumbprint = $CertificateThumbprint }
        else { $connect.ClientSecretCredential = [pscredential]::new($ClientId, $ClientSecret) }
        Connect-MgGraph @connect -ErrorAction Stop
        Add-ActionResult -Action 'GraphConnect' -State 'Completed' -Detail "Connected using AuthMethod=$AuthMethod" | Out-Null
        return $true
    }
    catch {
        Add-ActionResult -Action 'GraphConnect' -State 'Unknown' -Required $true -Detail "Connection failed: $($_.Exception.Message)" | Out-Null
        return $false
    }
}

function Get-LicenseSkuMap {
    if ($WhatIfPreference) { return @{} }
    $map = @{}
    try {
        foreach ($sku in @(Get-MgSubscribedSku -All -ErrorAction Stop)) { $map[$sku.SkuPartNumber] = $sku.SkuId }
        Add-ActionResult -Action 'ResolveLicenses' -State 'Completed' -Detail "Resolved $($map.Count) tenant SKU(s)." | Out-Null
    }
    catch {
        Add-ActionResult -Action 'ResolveLicenses' -State 'Unknown' -Required $true -Detail "SKU lookup failed: $($_.Exception.Message)" | Out-Null
    }
    return $map
}

function Invoke-ProvisioningRow {
    param([Parameter(Mandatory)][pscustomobject]$Row, [Parameter(Mandatory)][hashtable]$SkuMap, [int]$RowNumber)
    foreach ($column in $requiredColumns) {
        if (-not ($Row.PSObject.Properties.Name -contains $column) -or [string]::IsNullOrWhiteSpace([string]$Row.$column)) {
            Add-ActionResult -Action 'ValidateRow' -State 'Failed' -Required $true -Detail "Row $RowNumber is missing '$column'." | Out-Null
            return
        }
    }
    $usage = ([string]$Row.UsageLocation).Trim().ToUpperInvariant()
    if ($usage -notmatch '^[A-Z]{2}$') {
        Add-ActionResult -Action 'ValidateRow' -State 'Failed' -Required $true -Detail "Row $RowNumber UsageLocation must be a two-letter ISO-style value." | Out-Null
        return
    }
    $upn = "$(ConvertTo-MailToken $Row.FirstName).$(ConvertTo-MailToken $Row.LastName)@$UPNDomain"
    $validationState = if ($WhatIfPreference) { 'SkippedWhatIf' } else { 'Completed' }
    Add-ActionResult -Action 'ValidateRow' -State $validationState -UPN $upn -Detail "Row $RowNumber passed local validation; tenant policy still controls acceptance." | Out-Null
    if (-not $PSCmdlet.ShouldProcess($upn, 'Create Entra user and evaluate configured license assignment')) {
        Add-ActionResult -Action 'CreateUser' -State 'SkippedWhatIf' -Required $true -UPN $upn -Detail 'No lookup or write performed.' | Out-Null
        Add-ActionResult -Action 'AssignLicense' -State 'Planned' -UPN $upn -Detail 'License decision requires live SKU and tenant policy data.' | Out-Null
        return
    }

    try {
        $escaped = $upn -replace "'", "''"
        $existing = @(Get-MgUser -Filter "userPrincipalName eq '$escaped'" -ErrorAction Stop)
    }
    catch {
        Add-ActionResult -Action 'LookupUser' -State 'Unknown' -Required $true -UPN $upn -Detail "Lookup failed; creation stopped: $($_.Exception.Message)" | Out-Null
        return
    }
    if ($existing.Count -gt 1) {
        Add-ActionResult -Action 'LookupUser' -State 'Unknown' -Required $true -UPN $upn -Detail 'Lookup returned multiple users; creation stopped.' | Out-Null
        return
    }
    if ($existing.Count -eq 1) {
        Add-ActionResult -Action 'LookupUser' -State 'Failed' -Required $true -UPN $upn -Detail 'Existing user conflict; no reconciliation mode is implemented.' | Out-Null
        return
    }
    Add-ActionResult -Action 'LookupUser' -State 'Completed' -UPN $upn -Detail 'Confirmed missing by a successful exact-filter query.' | Out-Null

    $managerId = $null
    $manager = if ($Row.PSObject.Properties.Name -contains 'Manager') { ([string]$Row.Manager).Trim() } else { '' }
    if ($manager) {
        try {
            $escapedManager = $manager -replace "'", "''"
            $managerMatches = @(Get-MgUser -Filter "userPrincipalName eq '$escapedManager'" -ErrorAction Stop)
            if ($managerMatches.Count -eq 1) { $managerId = $managerMatches[0].Id }
            elseif ($managerMatches.Count -gt 1) { throw 'Manager lookup was ambiguous.' }
            else { Add-ActionResult -Action 'ResolveManager' -State 'Planned' -UPN $upn -Detail 'Manager was confirmed missing; manager assignment omitted.' | Out-Null }
        }
        catch {
            Add-ActionResult -Action 'ResolveManager' -State 'Unknown' -Required $true -UPN $upn -Detail "Manager lookup failed; user creation stopped: $($_.Exception.Message)" | Out-Null
            return
        }
    }

    $password = New-ComplexPassword
    $body = @{
        DisplayName = "$($Row.FirstName) $($Row.LastName)"; GivenName = $Row.FirstName; Surname = $Row.LastName
        UserPrincipalName = $upn; MailNickname = (ConvertTo-MailToken "$($Row.FirstName)$($Row.LastName)")
        Department = $Row.Department; JobTitle = $Row.Title; UsageLocation = $usage; AccountEnabled = $true
        PasswordProfile = @{ Password = $password; ForceChangePasswordNextSignIn = $true }
    }
    try {
        $newUser = New-MgUser -BodyParameter $body -ErrorAction Stop
        Add-ActionResult -Action 'CreateUser' -State 'Completed' -Required $true -UPN $upn -Detail "Created ObjectId=$($newUser.Id); no rollback is available." | Out-Null
    }
    catch {
        Add-ActionResult -Action 'CreateUser' -State 'Failed' -Required $true -UPN $upn -Detail "Creation failed: $($_.Exception.Message)" | Out-Null
        return
    }
    if ($managerId) {
        try {
            Set-MgUserManagerByRef -UserId $newUser.Id -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$managerId" } -ErrorAction Stop
            Add-ActionResult -Action 'SetManager' -State 'Completed' -UPN $upn -Detail "Manager set to ObjectId=$managerId" | Out-Null
        }
        catch { Add-ActionResult -Action 'SetManager' -State 'Failed' -UPN $upn -Detail "Manager assignment failed after user creation: $($_.Exception.Message)" | Out-Null }
    }

    $partNumber = if ($licensePartNumbers.ContainsKey([string]$Row.Department)) { $licensePartNumbers[[string]$Row.Department] } else { $licensePartNumbers.Default }
    $skuId = $SkuMap[$partNumber]
    if (-not $skuId) {
        Add-ActionResult -Action 'AssignLicense' -State 'Planned' -UPN $upn -Detail "No resolved SkuId for $partNumber; user exists without this license." | Out-Null
    }
    else {
        try {
            Set-MgUserLicense -UserId $newUser.Id -AddLicenses @(@{ SkuId = $skuId; DisabledPlans = @() }) -RemoveLicenses @() -ErrorAction Stop | Out-Null
            Add-ActionResult -Action 'AssignLicense' -State 'Completed' -Required $true -UPN $upn -Detail "Assigned configured SkuId=$skuId." | Out-Null
        }
        catch { Add-ActionResult -Action 'AssignLicense' -State 'Failed' -Required $true -UPN $upn -Detail "License assignment failed after user creation: $($_.Exception.Message)" | Out-Null }
    }
    if (-not $SuppressCredentialDisplay) {
        Write-Host "Temporary credential for approved secure delivery: $upn / $password" -ForegroundColor Yellow
    }
}

Write-WorkflowLog -Action 'Startup' -Message "Provisioning workflow started; AuthMethod=$authMethod; Mode=$(if ($WhatIfPreference) { 'WhatIf' } else { 'Live' })"
try {
    $queue = @(Import-Csv -LiteralPath $CsvPath -ErrorAction Stop)
    if (-not (Connect-WorkflowGraph -AuthMethod $authMethod)) { $queue = @() }
    $skuMap = Get-LicenseSkuMap
    for ($index = 0; $index -lt $queue.Count; $index++) { Invoke-ProvisioningRow -Row $queue[$index] -SkuMap $skuMap -RowNumber ($index + 2) }
}
catch {
    Add-ActionResult -Action 'Workflow' -State 'Failed' -Required $true -Detail $_.Exception.Message | Out-Null
}
finally {
    if (-not $WhatIfPreference) { try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {} }
}

$failedRequired = @($results | Where-Object { $_.Required -and $_.State -in @('Failed', 'Unknown') })
$completed = @($results | Where-Object State -eq 'Completed').Count
$planned = @($results | Where-Object State -in @('Planned', 'SkippedWhatIf')).Count
$final = [pscustomobject]@{
    Status = if ($failedRequired.Count -gt 0) { 'Failed' } elseif ($completed -gt 0) { 'PartialOrCompleted' } else { 'PlannedOnly' }
    Succeeded = ($failedRequired.Count -eq 0); CompletedCount = $completed; PlannedCount = $planned
    Results = @($results); RollbackAvailable = $false
}
Write-WorkflowLog -Action 'Summary' -Level $(if ($final.Succeeded) { 'INFO' } else { 'ERROR' }) -Message "FinalStatus=$($final.Status); Completed=$completed; PlannedOrSkipped=$planned; FailedRequired=$($failedRequired.Count); RollbackAvailable=false"
$final
if (-not $final.Succeeded) { throw 'Provisioning workflow ended with a failed or unknown required action.' }
