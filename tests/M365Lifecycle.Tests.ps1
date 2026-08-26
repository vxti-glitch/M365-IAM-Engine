BeforeAll {
    $provisioningScript = Join-Path $PSScriptRoot '..\Invoke-M365Provisioning.ps1'
    $offboardingScript = Join-Path $PSScriptRoot '..\Invoke-M365Offboarding.ps1'
    $tenantId = '00000000-0000-0000-0000-000000000001'
    $clientId = '00000000-0000-0000-0000-000000000002'
}

Describe 'Provisioning WhatIf safeguards' {
    BeforeEach {
        $csvPath = Join-Path $TestDrive 'onboarding.csv'
        @'
FirstName,LastName,Department,Title,UsageLocation,Manager
Jordan,Test,IT Support,Support Technician,US,
'@ | Set-Content -LiteralPath $csvPath -Encoding utf8
        $secret = ConvertTo-SecureString 'portfolio-test-secret' -AsPlainText -Force
    }

    It 'runs the client-secret path without loading Graph modules or making changes' {
        $logPath = Join-Path $TestDrive 'provision-client.log'

        & $provisioningScript -TenantId $tenantId -ClientId $clientId `
            -ClientSecret $secret -UPNDomain 'northstar.example' `
            -CsvPath $csvPath -LogPath $logPath -WhatIf

        $log = Get-Content -LiteralPath $logPath -Raw
        $log | Should -Match 'AuthMethod=ClientSecret'
        $log | Should -Match 'skipping actual Graph connection'
        $log | Should -Match 'WhatIf: User creation skipped'
        $log | Should -Not -Match 'portfolio-test-secret'
    }

    It 'preserves the certificate parameter set through the nested connector' {
        $logPath = Join-Path $TestDrive 'provision-certificate.log'

        & $provisioningScript -TenantId $tenantId -ClientId $clientId `
            -CertificateThumbprint 'AABBCCDDEEFF00112233445566778899AABBCCDD' `
            -UPNDomain 'northstar.example' -CsvPath $csvPath `
            -LogPath $logPath -WhatIf

        Get-Content -LiteralPath $logPath -Raw |
            Should -Match 'AuthMethod=Certificate'
    }
}

Describe 'Offboarding WhatIf safeguards' {
    It 'models offboarding without calling Microsoft Graph' {
        $logPath = Join-Path $TestDrive 'offboarding.log'
        $secret = ConvertTo-SecureString 'portfolio-test-secret' -AsPlainText -Force

        & $offboardingScript -UserPrincipalName 'jordan.test@northstar.example' `
            -TenantId $tenantId -ClientId $clientId -ClientSecret $secret `
            -LogPath $logPath -WhatIf

        $log = Get-Content -LiteralPath $logPath -Raw
        $log | Should -Match 'AuthMethod=ClientSecret'
        $log | Should -Match 'WhatIf: Skipping live lookup'
        $log | Should -Match 'Offboarding sequence complete'
        $log | Should -Not -Match 'portfolio-test-secret'
    }
}
