BeforeAll {
    $provisioningScript = Join-Path $PSScriptRoot '..\Invoke-M365Provisioning.ps1'
    $offboardingScript = Join-Path $PSScriptRoot '..\Invoke-M365Offboarding.ps1'
    $tenantId = '00000000-0000-0000-0000-000000000001'
    $clientId = '00000000-0000-0000-0000-000000000002'
    $secret = [SecureString]::new()
    'portfolio-test-secret'.ToCharArray() | ForEach-Object { $secret.AppendChar($_) }
    $secret.MakeReadOnly()

    function global:Connect-MgGraph { param($TenantId,$ClientId,$NoWelcome,$CertificateThumbprint,[pscredential]$ClientSecretCredential,$ErrorAction) $global:M365TestState.ConnectCalls++ }
    function global:Disconnect-MgGraph { param($ErrorAction) $global:M365TestState.DisconnectCalls++ }
    function global:Get-MgSubscribedSku {
        if ($global:M365TestState.SkuLookupFails) { throw 'tenant SKU lookup unavailable' }
        [pscustomobject]@{ SkuPartNumber = 'ENTERPRISEPREMIUM'; SkuId = 'sku-e5' }
        [pscustomobject]@{ SkuPartNumber = 'ENTERPRISEPACK'; SkuId = 'sku-e3' }
        [pscustomobject]@{ SkuPartNumber = 'O365_BUSINESS_PREMIUM'; SkuId = 'sku-bp' }
    }
    function global:Get-MgUser {
        param($UserId,$Filter,$Property,$ErrorAction)
        if ($global:M365TestState.LookupFails) { throw 'Graph service unavailable' }
        if ($PSBoundParameters.ContainsKey('UserId')) {
            return [pscustomobject]@{
                Id = 'user-1'; AccountEnabled = $true
                AssignedLicenses = @([pscustomobject]@{ SkuId = 'sku-e5' })
            }
        }
        if ($global:M365TestState.ExistingUser) { return [pscustomobject]@{ Id = 'existing-1' } }
        return @()
    }
    function global:New-MgUser {
        param($BodyParameter,$ErrorAction)
        $global:M365TestState.CreateCalls++
        [pscustomobject]@{ Id = 'created-1' }
    }
    function global:Set-MgUserLicense {
        param($UserId,$AddLicenses,$RemoveLicenses,$ErrorAction)
        $global:M365TestState.LicenseCalls++
        if ($global:M365TestState.LicenseFails) { throw 'license assignment failed' }
    }
    function global:Set-MgUserManagerByRef { param($UserId,$BodyParameter,$ErrorAction) $global:M365TestState.ManagerCalls++ }
    function global:Update-MgUser { param($UserId,$AccountEnabled,$ErrorAction) $global:M365TestState.DisableCalls++ }
    function global:Revoke-MgUserSignInSession { param($UserId,$ErrorAction) $global:M365TestState.RevokeCalls++; return $true }

    function Reset-M365TestState {
        $global:M365TestState = @{
            ConnectCalls = 0; DisconnectCalls = 0; CreateCalls = 0; LicenseCalls = 0
            ManagerCalls = 0; DisableCalls = 0; RevokeCalls = 0
            LookupFails = $false; ExistingUser = $false; LicenseFails = $false; SkuLookupFails = $false
        }
    }
}

AfterAll {
    'Connect-MgGraph','Disconnect-MgGraph','Get-MgSubscribedSku','Get-MgUser','New-MgUser',
    'Set-MgUserLicense','Set-MgUserManagerByRef','Update-MgUser','Revoke-MgUserSignInSession' |
        ForEach-Object { Remove-Item "function:global:$_" -ErrorAction SilentlyContinue }
    Remove-Variable M365TestState -Scope Global -ErrorAction SilentlyContinue
}

Describe 'Provisioning validation and result states' {
    BeforeEach {
        Reset-M365TestState
        $csvPath = Join-Path $TestDrive 'onboarding.csv'
        @'
FirstName,LastName,Department,Title,UsageLocation,Manager
Jordan,Test,IT Support,Support Technician,US,
'@ | Set-Content -LiteralPath $csvPath -Encoding utf8
    }

    It 'uses explicit client-secret auth and emits no completed outcome under WhatIf' {
        $logPath = Join-Path $TestDrive 'provision-whatif.log'
        $result = & $provisioningScript -TenantId $tenantId -ClientId $clientId -ClientSecret $secret `
            -UPNDomain 'northstar.example' -CsvPath $csvPath -LogPath $logPath -WhatIf
        $log = Get-Content -LiteralPath $logPath -Raw

        $result.Status | Should -Be 'PlannedOnly'
        $log | Should -Match 'AuthMethod=ClientSecret'
        $log | Should -Match 'State=SkippedWhatIf'
        $log | Should -Not -Match '\[SUCCESS\]|Provisioning complete'
        $global:M365TestState.ConnectCalls | Should -Be 0
    }

    It 'preserves certificate auth through the nested connector' {
        $logPath = Join-Path $TestDrive 'provision-certificate.log'
        & $provisioningScript -TenantId $tenantId -ClientId $clientId `
            -CertificateThumbprint 'AABBCCDDEEFF00112233445566778899AABBCCDD' `
            -UPNDomain 'northstar.example' -CsvPath $csvPath -LogPath $logPath -WhatIf | Out-Null
        Get-Content -LiteralPath $logPath -Raw | Should -Match 'AuthMethod=Certificate'
    }

    It 'rejects an invalid UsageLocation before any user lookup or write' {
        (Get-Content $csvPath -Raw).Replace(',US,', ',USA,') | Set-Content $csvPath
        $logPath = Join-Path $TestDrive 'invalid-location.log'
        { & $provisioningScript -TenantId $tenantId -ClientId $clientId -ClientSecret $secret `
            -UPNDomain 'northstar.example' -CsvPath $csvPath -LogPath $logPath -SuppressCredentialDisplay } | Should -Throw
        Get-Content $logPath -Raw | Should -Match 'UsageLocation must be a two-letter ISO-style value'
        $global:M365TestState.CreateCalls | Should -Be 0
    }

    It 'stops on an existing user conflict' {
        $global:M365TestState.ExistingUser = $true
        $logPath = Join-Path $TestDrive 'existing.log'
        { & $provisioningScript -TenantId $tenantId -ClientId $clientId -ClientSecret $secret `
            -UPNDomain 'northstar.example' -CsvPath $csvPath -LogPath $logPath -SuppressCredentialDisplay } | Should -Throw
        Get-Content $logPath -Raw | Should -Match 'Existing user conflict'
        $global:M365TestState.CreateCalls | Should -Be 0
    }

    It 'fails closed when the user lookup is unknown' {
        $global:M365TestState.LookupFails = $true
        $logPath = Join-Path $TestDrive 'lookup-unknown.log'
        { & $provisioningScript -TenantId $tenantId -ClientId $clientId -ClientSecret $secret `
            -UPNDomain 'northstar.example' -CsvPath $csvPath -LogPath $logPath -SuppressCredentialDisplay } | Should -Throw
        Get-Content $logPath -Raw | Should -Match 'State=Unknown; Lookup failed; creation stopped'
        $global:M365TestState.CreateCalls | Should -Be 0
    }

    It 'reports partial failure and a failed final status after license failure' {
        $global:M365TestState.LicenseFails = $true
        $logPath = Join-Path $TestDrive 'partial.log'
        { & $provisioningScript -TenantId $tenantId -ClientId $clientId -ClientSecret $secret `
            -UPNDomain 'northstar.example' -CsvPath $csvPath -LogPath $logPath -SuppressCredentialDisplay } | Should -Throw
        $log = Get-Content $logPath -Raw
        $log | Should -Match 'Action=CreateUser \| State=Completed'
        $log | Should -Match 'Action=AssignLicense \| State=Failed'
        $log | Should -Match 'FinalStatus=Failed'
        $global:M365TestState.CreateCalls | Should -Be 1
    }
}

Describe 'Offboarding approvals and WhatIf truthfulness' {
    BeforeEach { Reset-M365TestState }

    It 'keeps all policy actions planned by default' {
        $logPath = Join-Path $TestDrive 'offboarding-default.log'
        $result = & $offboardingScript -UserPrincipalName 'jordan.test@northstar.example' `
            -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -LogPath $logPath
        $result.Status | Should -Be 'PartialOrCompleted'
        $global:M365TestState.DisableCalls | Should -Be 0
        $global:M365TestState.RevokeCalls | Should -Be 0
        $global:M365TestState.LicenseCalls | Should -Be 0
        Get-Content $logPath -Raw | Should -Match 'Action=RemoveLicenses \| State=Planned'
    }

    It 'requires both license approval and prerequisite confirmation' {
        $logPath = Join-Path $TestDrive 'license-no-prereq.log'
        & $offboardingScript -UserPrincipalName 'jordan.test@northstar.example' `
            -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -LogPath $logPath `
            -ApproveLicenseRemoval | Out-Null
        $global:M365TestState.LicenseCalls | Should -Be 0
        Get-Content $logPath -Raw | Should -Match 'prerequisites are not confirmed'
    }

    It 'runs approved actions only when every guard is present' {
        $logPath = Join-Path $TestDrive 'offboarding-approved.log'
        & $offboardingScript -UserPrincipalName 'jordan.test@northstar.example' `
            -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -LogPath $logPath `
            -ApproveDisableSignIn -ApproveSessionRevocation -ApproveLicenseRemoval `
            -LicensePrerequisitesConfirmed | Out-Null
        $global:M365TestState.DisableCalls | Should -Be 1
        $global:M365TestState.RevokeCalls | Should -Be 1
        $global:M365TestState.LicenseCalls | Should -Be 1
        Get-Content $logPath -Raw | Should -Match 'Action=RemoveLicenses \| State=Completed'
    }

    It 'uses SkippedWhatIf and never claims completed outcomes in preview' {
        $logPath = Join-Path $TestDrive 'offboarding-whatif.log'
        & $offboardingScript -UserPrincipalName 'jordan.test@northstar.example' `
            -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -LogPath $logPath `
            -ApproveDisableSignIn -ApproveSessionRevocation -ApproveLicenseRemoval `
            -LicensePrerequisitesConfirmed -WhatIf | Out-Null
        $log = Get-Content $logPath -Raw
        $log | Should -Match 'State=SkippedWhatIf'
        $log | Should -Not -Match '\[SUCCESS\]|sessions revoked|licenses stripped|offboarding complete'
        $global:M365TestState.ConnectCalls | Should -Be 0
        $global:M365TestState.DisableCalls | Should -Be 0
    }

    It 'returns a failed final status for an unknown required lookup' {
        $global:M365TestState.LookupFails = $true
        $logPath = Join-Path $TestDrive 'offboarding-lookup-fail.log'
        { & $offboardingScript -UserPrincipalName 'jordan.test@northstar.example' `
            -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -LogPath $logPath } | Should -Throw
        Get-Content $logPath -Raw | Should -Match 'FinalStatus=Failed'
        $global:M365TestState.DisableCalls | Should -Be 0
    }
}
