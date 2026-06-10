#Requires -Version 7.0

BeforeAll {
    $script:dscModuleName = 'Get-EntraZTAssess'

    <#
        Prefer an installed or built module; fall back to the source manifest
        so bare Invoke-Pester works without a prior build or PSModulePath
        registration.
    #>
    if (Get-Module -ListAvailable -Name $script:dscModuleName -ErrorAction SilentlyContinue) {
        Import-Module -Name $script:dscModuleName -Force
    }
    else {
        Import-Module -Name (Join-Path $PSScriptRoot '../../../source/Get-EntraZTAssess.psd1') -Force
    }

    . (Join-Path $PSScriptRoot '../../Fixtures/FixtureHelper.ps1')
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Test-ZTAssessHybridIdentity' -Tag 'Unit' {

    Context 'When the hybrid tenant is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessHybridIdentity -RunPath $runPath
            }
        }

        It 'Should emit a finding for every hybrid identity check' {
            $script:findings.Count | Should -Be 6
        }

        It 'Should pass check <_>' -ForEach @('HY-001', 'HY-002', 'HY-003') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }

        It 'Should mark the manual verification items appropriately' {
            ($script:findings | Where-Object CheckId -eq 'HY-004').Status | Should -Be 'NotAssessed'
            ($script:findings | Where-Object CheckId -eq 'HY-005').Status | Should -Be 'Informational'
            ($script:findings | Where-Object CheckId -eq 'HY-006').Status | Should -Be 'NotAssessed'
        }
    }

    Context 'When the tenant is cloud-only' {
        It 'Should mark every check NotAssessed with a cloud-only reason' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'cloud-only') -Overrides @{
                organization = @(@{ id = 'tenant-1'; displayName = 'Contoso Ltd'; onPremisesSyncEnabled = $false })
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessHybridIdentity -RunPath $runPath
            }

            $findings.Count | Should -Be 6
            ($findings | Where-Object Status -ne 'NotAssessed').Count | Should -Be 0
            $findings[0].NotAssessedReason | Should -Match 'Cloud-only'
        }
    }

    Context 'When synchronisation has stalled' {
        It 'Should fail HY-002 beyond the failure threshold' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'stale-sync') -Overrides @{
                organization = @(@{ id = 'tenant-1'; displayName = 'Contoso Ltd'; onPremisesSyncEnabled = $true; onPremisesLastSyncDateTime = [datetime]::UtcNow.AddHours(-30).ToString('yyyy-MM-ddTHH:mm:ssZ') })
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessHybridIdentity -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'HY-002').Status | Should -Be 'Fail'
        }
    }

    Context 'When password hash sync is disabled' {
        It 'Should fail HY-001' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-phs') -Overrides @{
                onPremisesSynchronization = @(
                    @{ id = 'sync-1'; features = @{ passwordSyncEnabled = $false; deviceWritebackEnabled = $false; groupWriteBackEnabled = $false } }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessHybridIdentity -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'HY-001').Status | Should -Be 'Fail'
        }
    }

    Context 'When provisioning errors exceed the threshold' {
        It 'Should fail HY-003' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'sync-errors') -Overrides @{
                provisioningErrorsSummary = @{ syncedUserCount = 100; usersWithErrors = 5; errorsByCategory = @(@{ category = 'PropertyConflict'; count = 5 }) }
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessHybridIdentity -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'HY-003').Status | Should -Be 'Fail'
        }
    }
}
