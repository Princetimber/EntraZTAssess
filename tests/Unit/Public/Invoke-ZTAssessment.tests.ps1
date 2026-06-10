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
    InModuleScope -ModuleName 'Get-EntraZTAssess' {
        $script:ZTAssessConnection = $null
    }
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Invoke-ZTAssessment' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:dscModuleName -CommandName Write-ToLog -MockWith { }
        Mock -ModuleName $script:dscModuleName -CommandName Set-LogFilePath -MockWith { }

        # Fake an established connection.
        InModuleScope -ModuleName $script:dscModuleName {
            $script:ZTAssessConnection = [pscustomobject]@{
                TenantId       = 'tenant-1'
                Account        = 'consultant@contoso.com'
                AuthMode       = 'Delegated'
                Environment    = 'Global'
                Modules        = @('Identity', 'ConditionalAccess', 'PrivilegedAccess')
                RequiredScopes = @()
                GrantedScopes  = @('Directory.Read.All')
                MissingScopes  = @()
            }
        }

        # Replace network collectors with fixture writers.
        Mock -ModuleName $script:dscModuleName -CommandName Invoke-ZTAssessCoreCollection -MockWith {
            New-ZTAssessTestRun -Path $RunPath | Out-Null
            @{ core = @{ Success = $true; RecordCount = 1; DurationSeconds = 0.1; Error = $null } }
        }
        Mock -ModuleName $script:dscModuleName -CommandName Invoke-ZTAssessIdentityCollection -MockWith { @{} }
        Mock -ModuleName $script:dscModuleName -CommandName Invoke-ZTAssessConditionalAccessCollection -MockWith { @{} }
        Mock -ModuleName $script:dscModuleName -CommandName Invoke-ZTAssessPrivilegedAccessCollection -MockWith { @{} }
        Mock -ModuleName $script:dscModuleName -CommandName Invoke-ZTAssessDeviceCollection -MockWith { @{} }
        Mock -ModuleName $script:dscModuleName -CommandName Invoke-ZTAssessGovernanceCollection -MockWith { @{} }
        Mock -ModuleName $script:dscModuleName -CommandName Invoke-ZTAssessApplicationCollection -MockWith { @{} }
        Mock -ModuleName $script:dscModuleName -CommandName Invoke-ZTAssessHybridCollection -MockWith { @{} }
        Mock -ModuleName $script:dscModuleName -CommandName Invoke-ZTAssessMonitoringCollection -MockWith { @{} }

        # Engagement scaffold.
        $script:engagementPath = Join-Path $TestDrive "engagement-$([guid]::NewGuid().ToString('n').Substring(0,8))"
        $null = New-Item -Path (Join-Path $script:engagementPath 'Runs') -ItemType Directory -Force
        Set-Content -Path (Join-Path $script:engagementPath 'engagement.psd1') -Value "@{ CustomerName = 'Contoso'; Reference = 'ENG-1' }"
    }

    Context 'When running a full Phase 1 assessment' {
        It 'Should produce findings, scores, and a manifest in a new run folder' {
            $summary = Invoke-ZTAssessment -EngagementPath $script:engagementPath

            $summary.RunPath | Should -Not -BeNullOrEmpty
            Test-Path (Join-Path $summary.RunPath 'Findings/findings.json') | Should -BeTrue
            Test-Path (Join-Path $summary.RunPath 'Scores/scores.json') | Should -BeTrue
            Test-Path (Join-Path $summary.RunPath 'manifest.json') | Should -BeTrue
            Test-Path (Join-Path $summary.RunPath 'Raw/_collectionStatus.json') | Should -BeTrue
        }

        It 'Should emit all 35 findings and a high score for the well-configured fixture' {
            $summary = Invoke-ZTAssessment -EngagementPath $script:engagementPath

            $findings = Get-Content (Join-Path $summary.RunPath 'Findings/findings.json') -Raw | ConvertFrom-Json -Depth 20
            @($findings).Count | Should -Be 35

            $summary.OverallScorePercent | Should -BeGreaterThan 85
            $summary.OverallLevel | Should -Be 'Optimised'
            $summary.RiskPosture | Should -Be 'Managed Risk'
        }

        It 'Should record the connection identity in the manifest' {
            $summary = Invoke-ZTAssessment -EngagementPath $script:engagementPath

            $manifest = Get-Content (Join-Path $summary.RunPath 'manifest.json') -Raw | ConvertFrom-Json
            $manifest.TenantId | Should -Be 'tenant-1'
            $manifest.AuthMode | Should -Be 'Delegated'
            @($manifest.Modules) | Should -Contain 'Identity'
        }
    }

    Context 'When running a subset of modules' {
        It 'Should assess only the selected module' {
            $summary = Invoke-ZTAssessment -EngagementPath $script:engagementPath -Modules ConditionalAccess

            $findings = Get-Content (Join-Path $summary.RunPath 'Findings/findings.json') -Raw | ConvertFrom-Json -Depth 20
            @($findings).Count | Should -Be 13
            (@($findings).Domain | Sort-Object -Unique) | Should -Be 'ConditionalAccess'
        }
    }

    Context 'When running the Devices module' {
        It 'Should emit the 32 device findings and persist classification and platform profiles' {
            $summary = Invoke-ZTAssessment -EngagementPath $script:engagementPath -Modules Devices

            $findings = Get-Content (Join-Path $summary.RunPath 'Findings/findings.json') -Raw | ConvertFrom-Json -Depth 20
            @($findings).Count | Should -Be 32
            (@($findings).Domain | Sort-Object -Unique) | Should -Be @('ByodGovernance', 'CorporateDeviceGovernance', 'DeviceTrust', 'EndpointManagement')

            Test-Path (Join-Path $summary.RunPath 'Findings/deviceClassification.json') | Should -BeTrue
            Test-Path (Join-Path $summary.RunPath 'Findings/platformProfiles.json') | Should -BeTrue

            $profiles = Get-Content (Join-Path $summary.RunPath 'Findings/platformProfiles.json') -Raw | ConvertFrom-Json -Depth 20
            @($profiles).Platform | Should -Contain 'Windows'
            @($profiles).Platform | Should -Contain 'Android'
        }
    }

    Context 'When running the Phase 3 modules' {
        It 'Should emit the 25 governance, application, hybrid, and monitoring findings' {
            $summary = Invoke-ZTAssessment -EngagementPath $script:engagementPath -Modules IdentityGovernance, Applications, HybridIdentity, Monitoring

            $findings = Get-Content (Join-Path $summary.RunPath 'Findings/findings.json') -Raw | ConvertFrom-Json -Depth 20
            @($findings).Count | Should -Be 25
            (@($findings).Domain | Sort-Object -Unique) | Should -Be @('ApplicationSecurity', 'HybridIdentity', 'IdentityGovernance', 'MonitoringDetection')
        }
    }

    Context 'When running every implemented module' {
        It 'Should emit all 92 findings' {
            $summary = Invoke-ZTAssessment -EngagementPath $script:engagementPath -Modules Identity, ConditionalAccess, PrivilegedAccess, Devices, IdentityGovernance, Applications, HybridIdentity, Monitoring

            $findings = Get-Content (Join-Path $summary.RunPath 'Findings/findings.json') -Raw | ConvertFrom-Json -Depth 20
            @($findings).Count | Should -Be 92
            (@($findings).Domain | Sort-Object -Unique).Count | Should -Be 11
        }
    }

    Context 'When unsupported modules are requested' {
        It 'Should warn and skip them' {
            $summary = Invoke-ZTAssessment -EngagementPath $script:engagementPath -Modules Identity, Sentinel -WarningVariable runWarnings -WarningAction SilentlyContinue

            $runWarnings | Should -Not -BeNullOrEmpty
            $summary.Modules | Should -Not -Contain 'Sentinel'
        }

        It 'Should fail when no supported module remains' {
            { Invoke-ZTAssessment -EngagementPath $script:engagementPath -Modules Sentinel -ErrorAction Stop -WarningAction SilentlyContinue } |
                Should -Throw -ExpectedMessage '*No supported modules*'
        }
    }

    Context 'When no connection exists' {
        It 'Should instruct the user to connect first' {
            InModuleScope -ModuleName $script:dscModuleName {
                $script:ZTAssessConnection = $null
            }

            { Invoke-ZTAssessment -EngagementPath $script:engagementPath -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*Connect-ZTAssessment*'
        }
    }

    Context 'When the engagement path is invalid' {
        It 'Should reject a folder without engagement.psd1' {
            $bare = Join-Path $TestDrive 'not-an-engagement'
            $null = New-Item -Path $bare -ItemType Directory

            { Invoke-ZTAssessment -EngagementPath $bare } | Should -Throw
        }
    }
}
