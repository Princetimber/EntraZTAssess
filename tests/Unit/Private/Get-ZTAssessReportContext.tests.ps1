#Requires -Version 7.0

BeforeAll {
    $script:dscModuleName = 'Get-EntraZTAssess'

    if (Get-Module -ListAvailable -Name $script:dscModuleName -ErrorAction SilentlyContinue) {
        Import-Module -Name $script:dscModuleName -Force
    }
    else {
        Import-Module -Name (Join-Path $PSScriptRoot '../../../source/Get-EntraZTAssess.psd1') -Force
    }
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Get-ZTAssessReportContext' -Tag 'Unit' {
    It 'Should load required and optional run artifacts without Graph access' {
        InModuleScope -ModuleName $script:dscModuleName {
            $engagementPath = Join-Path $TestDrive 'Contoso-ENG-002'
            $runPath = Join-Path $engagementPath 'Runs/20260610-130000'
            $null = New-Item -Path (Join-Path $runPath 'Findings') -ItemType Directory -Force
            $null = New-Item -Path (Join-Path $runPath 'Scores') -ItemType Directory -Force

            "@{ CustomerName = 'Contoso'; Reference = 'ENG-002'; Classification = 'Official'; Branding = @{} }" |
                Set-Content -LiteralPath (Join-Path $engagementPath 'engagement.psd1') -Encoding utf8NoBOM
            @(@{ CheckId = 'CA-001'; Status = 'Fail'; Severity = 'Critical' }) |
                ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $runPath 'Findings/findings.json') -Encoding utf8NoBOM
            @{ OverallScorePercent = 50; Domains = @(); Pillars = @(); RiskCounts = @{} } |
                ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $runPath 'Scores/scores.json') -Encoding utf8NoBOM
            @{ TenantId = 'tenant-optional' } |
                ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $runPath 'manifest.json') -Encoding utf8NoBOM
            @(@{ Platform = 'iOS' }) |
                ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $runPath 'Findings/platformProfiles.json') -Encoding utf8NoBOM
            @(@{ DeviceId = 'device-2'; Class = 'BYOD' }) |
                ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $runPath 'Findings/deviceClassification.json') -Encoding utf8NoBOM

            $context = Get-ZTAssessReportContext -RunPath $runPath

            $context.PSTypeNames[0] | Should -Be 'ZTAssess.ReportContext'
            $context.Manifest.TenantId | Should -Be 'tenant-optional'
            @($context.PlatformProfiles).Count | Should -Be 1
            @($context.DeviceClassification).Count | Should -Be 1
            $context.Engagement.CustomerName | Should -Be 'Contoso'
        }
    }

    It 'Should throw actionable errors for missing required artifacts' {
        InModuleScope -ModuleName $script:dscModuleName {
            $runPath = Join-Path $TestDrive 'empty-run'
            $null = New-Item -Path $runPath -ItemType Directory -Force

            { Get-ZTAssessReportContext -RunPath $runPath } | Should -Throw -ExpectedMessage '*findings.json*'
        }
    }
}
