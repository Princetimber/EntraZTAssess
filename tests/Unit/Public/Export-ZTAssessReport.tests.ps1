#Requires -Version 7.0

BeforeAll {
    $script:dscModuleName = 'Get-EntraZTAssess'

    if (Get-Module -ListAvailable -Name $script:dscModuleName -ErrorAction SilentlyContinue) {
        Import-Module -Name $script:dscModuleName -Force
    }
    else {
        Import-Module -Name (Join-Path $PSScriptRoot '../../../source/Get-EntraZTAssess.psd1') -Force
    }

    function New-TestReportRun {
        param(
            [Parameter(Mandatory)]
            [string]$Root,

            [Parameter()]
            [switch]$IncludeOptionalArtifacts
        )

        $engagementPath = Join-Path $Root 'Contoso-ENG-001'
        $runPath = Join-Path $engagementPath 'Runs/20260610-120000'
        $null = New-Item -Path (Join-Path $runPath 'Findings') -ItemType Directory -Force
        $null = New-Item -Path (Join-Path $runPath 'Scores') -ItemType Directory -Force

        @"
@{
    CustomerName = 'Contoso <Research>'
    Reference = 'ENG-001'
    Classification = 'Confidential - Client'
    Branding = @{}
}
"@ | Set-Content -LiteralPath (Join-Path $engagementPath 'engagement.psd1') -Encoding utf8NoBOM

        @(
            [ordered]@{
                CheckId = 'CA-001'; Domain = 'ConditionalAccess'; Title = 'Require MFA <all users>'; Status = 'Fail'; Severity = 'Critical'
                Evidence = 'Policy missing for <All users>'; Rationale = 'Attackers can sign in'; Remediation = 'Create CA policy'; RemediationEffort = 'Medium'
                ZeroTrustPillars = @('VerifyExplicitly', 'LeastPrivilege'); References = @('https://learn.microsoft.com/a', 'https://learn.microsoft.com/b')
            }
            [ordered]@{
                CheckId = 'PA-001'; Domain = 'PrivilegedAccess'; Title = 'Too many admins'; Status = 'Partial'; Severity = 'High'
                Evidence = '6 admins'; Rationale = 'Standing access'; Remediation = 'Reduce role assignments'; RemediationEffort = 'Low'
                ZeroTrustPillars = @('LeastPrivilege'); References = @('https://learn.microsoft.com/c')
            }
            [ordered]@{
                CheckId = 'ID-001'; Domain = 'IdentitySecurity'; Title = 'MFA registration'; Status = 'Pass'; Severity = 'None'
                Evidence = '98% registered'; Rationale = 'Good coverage'; Remediation = ''; RemediationEffort = ''
                ZeroTrustPillars = @('VerifyExplicitly'); References = @()
            }
            [ordered]@{
                CheckId = 'MD-001'; Domain = 'MonitoringDetection'; Title = 'Audit logs unavailable'; Status = 'NotAssessed'; Severity = 'None'
                Evidence = ''; Rationale = ''; Remediation = ''; RemediationEffort = ''; NotAssessedReason = 'Missing AuditLog.Read.All grant.'
                ZeroTrustPillars = @('AssumeBreach'); References = @()
            }
        ) | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $runPath 'Findings/findings.json') -Encoding utf8NoBOM

        [ordered]@{
            OverallScorePercent = 64
            OverallLevel = 'Managed'
            RiskPosture = 'At Risk'
            RiskCounts = [ordered]@{ Critical = 1; High = 1; Medium = 0; Low = 0 }
            Domains = @(
                [ordered]@{ Domain = 'ConditionalAccess'; ScorePercent = 25; Level = 'Initial' }
                [ordered]@{ Domain = 'PrivilegedAccess'; ScorePercent = 50; Level = 'Developing' }
                [ordered]@{ Domain = 'IdentitySecurity'; ScorePercent = 100; Level = 'Optimised' }
            )
            Pillars = @(
                [ordered]@{ Pillar = 'VerifyExplicitly'; ScorePercent = 60; Level = 'Managed' }
                [ordered]@{ Pillar = 'LeastPrivilege'; ScorePercent = 50; Level = 'Developing' }
            )
        } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $runPath 'Scores/scores.json') -Encoding utf8NoBOM

        [ordered]@{ TenantId = 'tenant-123'; Modules = @('Identity', 'ConditionalAccess'); StartedUtc = '2026-06-10T12:00:00Z'; CompletedUtc = '2026-06-10T12:05:00Z' } |
            ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $runPath 'manifest.json') -Encoding utf8NoBOM

        if ($IncludeOptionalArtifacts) {
            @([ordered]@{ Platform = 'Windows'; Managed = 42; Compliant = 40 }) |
                ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $runPath 'Findings/platformProfiles.json') -Encoding utf8NoBOM
            @([ordered]@{ DeviceId = 'device-1'; Class = 'Corporate'; Confidence = 'High' }) |
                ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $runPath 'Findings/deviceClassification.json') -Encoding utf8NoBOM
        }

        return $runPath
    }
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Export-ZTAssessReport' -Tag 'Unit' {
    Context 'When exporting a completed run' {
        It 'Should write the Phase 4 MVP report artifacts and return a structured result' {
            $runPath = New-TestReportRun -Root $TestDrive -IncludeOptionalArtifacts

            $result = Export-ZTAssessReport -RunPath $runPath

            $result.PSTypeNames[0] | Should -Be 'ZTAssess.ReportExportResult'
            $result.RunPath | Should -Be $runPath
            $result.ReportsPath | Should -Be (Join-Path $runPath 'Reports')
            $result.GeneratedUtc | Should -BeOfType ([datetime])

            foreach ($path in @($result.ExecutiveReportPath, $result.TechnicalReportPath, $result.RiskRegisterJsonPath, $result.RiskRegisterCsvPath, $result.RemediationRoadmapJsonPath)) {
                Test-Path -LiteralPath $path -PathType Leaf | Should -BeTrue
            }
        }

        It 'Should include only Fail and Partial findings in the risk register and roadmap' {
            $runPath = New-TestReportRun -Root $TestDrive

            $result = Export-ZTAssessReport -RunPath $runPath
            $riskRegister = Get-Content -LiteralPath $result.RiskRegisterJsonPath -Raw | ConvertFrom-Json -Depth 20
            $roadmap = Get-Content -LiteralPath $result.RemediationRoadmapJsonPath -Raw | ConvertFrom-Json -Depth 20

            @($riskRegister).CheckId | Should -Be @('CA-001', 'PA-001')
            @($roadmap).CheckId | Should -Be @('CA-001', 'PA-001')
            @($riskRegister).CheckId | Should -Not -Contain 'ID-001'
            @($riskRegister).CheckId | Should -Not -Contain 'MD-001'
        }

        It 'Should flatten CSV array fields deterministically' {
            $runPath = New-TestReportRun -Root $TestDrive

            $result = Export-ZTAssessReport -RunPath $runPath
            $csv = Import-Csv -LiteralPath $result.RiskRegisterCsvPath

            $csv[0].CheckId | Should -Be 'CA-001'
            $csv[0].ZeroTrustPillars | Should -Be 'LeastPrivilege; VerifyExplicitly'
            $csv[0].References | Should -Be 'https://learn.microsoft.com/a; https://learn.microsoft.com/b'
        }
    }

    Context 'When the run is incomplete' {
        It 'Should reject a folder without findings.json' {
            $runPath = Join-Path $TestDrive 'missing-findings'
            $null = New-Item -Path (Join-Path $runPath 'Scores') -ItemType Directory -Force
            '{}' | Set-Content -LiteralPath (Join-Path $runPath 'Scores/scores.json') -Encoding utf8NoBOM

            { Export-ZTAssessReport -RunPath $runPath } | Should -Throw -ExpectedMessage '*findings.json*'
        }

        It 'Should reject a folder without scores.json' {
            $runPath = Join-Path $TestDrive 'missing-scores'
            $null = New-Item -Path (Join-Path $runPath 'Findings') -ItemType Directory -Force
            '[]' | Set-Content -LiteralPath (Join-Path $runPath 'Findings/findings.json') -Encoding utf8NoBOM

            { Export-ZTAssessReport -RunPath $runPath } | Should -Throw -ExpectedMessage '*scores.json*'
        }
    }

    Context 'When using -WhatIf' {
        It 'Should not create the Reports folder or write artifacts' {
            $runPath = New-TestReportRun -Root $TestDrive

            $result = Export-ZTAssessReport -RunPath $runPath -WhatIf

            $result.PSTypeNames[0] | Should -Be 'ZTAssess.ReportExportResult'
            Test-Path -LiteralPath (Join-Path $runPath 'Reports') | Should -BeFalse
        }
    }
}
