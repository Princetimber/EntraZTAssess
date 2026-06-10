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

    # Build a run folder with a scores.json fixture.
    $script:runPath = Join-Path $TestDrive 'run-1'
    $null = New-Item -Path (Join-Path $script:runPath 'Scores') -ItemType Directory -Force

    @{
        OverallScorePercent = 72.5
        OverallLevel        = 'Advanced'
        RiskPosture         = 'Needs Attention'
        RiskCounts          = @{ Critical = 0; High = 2; Medium = 3; Low = 1 }
        Domains             = @(
            @{ Domain = 'IdentitySecurity'; ScorePercent = 80.0; Level = 'Advanced' }
            @{ Domain = 'ConditionalAccess'; ScorePercent = 65.0; Level = 'Managed' }
        )
        Pillars             = @(
            @{ Pillar = 'VerifyExplicitly'; ScorePercent = 75.0; Level = 'Advanced' }
        )
    } | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $script:runPath 'Scores/scores.json') -Encoding utf8NoBOM
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Get-ZTAssessScore' -Tag 'Unit' {

    Context 'When reading a persisted run' {
        It 'Should return the full score summary' {
            $scores = Get-ZTAssessScore -RunPath $script:runPath

            $scores.OverallScorePercent | Should -Be 72.5
            $scores.OverallLevel | Should -Be 'Advanced'
            $scores.RiskPosture | Should -Be 'Needs Attention'
            $scores.RiskCounts.High | Should -Be 2
            @($scores.Domains).Count | Should -Be 2
            @($scores.Pillars)[0].Pillar | Should -Be 'VerifyExplicitly'
        }
    }

    Context 'When the run path is invalid' {
        It 'Should reject a folder without scores.json' {
            $bare = Join-Path $TestDrive 'no-scores'
            $null = New-Item -Path $bare -ItemType Directory

            { Get-ZTAssessScore -RunPath $bare } | Should -Throw
        }
    }
}
