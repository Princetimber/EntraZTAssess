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
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'New-ZTAssessEngagement' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:dscModuleName -CommandName Write-ToLog -MockWith { }
    }

    Context 'When scaffolding a new engagement' {
        It 'Should create the engagement folder with a Runs subfolder' {
            $result = New-ZTAssessEngagement -CustomerName 'Contoso Ltd' -Reference 'ENG-2026-042' -OutputPath $TestDrive

            Test-Path -LiteralPath $result.EngagementPath -PathType Container | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.EngagementPath 'Runs') -PathType Container | Should -BeTrue
        }

        It 'Should derive a folder-safe name from the customer name and reference' {
            $result = New-ZTAssessEngagement -CustomerName 'Contoso Ltd' -Reference 'ENG-2026-043' -OutputPath $TestDrive

            Split-Path -Leaf $result.EngagementPath | Should -Be 'Contoso-Ltd-ENG-2026-043'
        }

        It 'Should write a parseable engagement.psd1 capturing the inputs' {
            $result = New-ZTAssessEngagement -CustomerName "O'Neill & Sons" -Reference 'ENG-2026-007' -OutputPath $TestDrive -Classification 'Official-Sensitive'

            Test-Path -LiteralPath $result.SettingsPath -PathType Leaf | Should -BeTrue

            $settings = Import-PowerShellDataFile -LiteralPath $result.SettingsPath
            $settings.CustomerName | Should -Be "O'Neill & Sons"
            $settings.Reference | Should -Be 'ENG-2026-007'
            $settings.Classification | Should -Be 'Official-Sensitive'
            $settings.Branding | Should -Not -BeNullOrEmpty
            $settings.ContainsKey('ThresholdOverrides') | Should -BeTrue
        }

        It 'Should default the classification to Confidential' {
            $result = New-ZTAssessEngagement -CustomerName 'Fabrikam' -Reference 'ENG-1' -OutputPath $TestDrive

            (Import-PowerShellDataFile -LiteralPath $result.SettingsPath).Classification | Should -Be 'Confidential'
        }
    }

    Context 'When inputs are invalid' {
        It 'Should reject a reference containing unsafe characters' {
            { New-ZTAssessEngagement -CustomerName 'Contoso' -Reference 'ENG 2026/042' -OutputPath $TestDrive } |
                Should -Throw
        }

        It 'Should create the output path when it does not exist' {
            $missingParent = Join-Path $TestDrive 'not-yet/nested'

            $result = New-ZTAssessEngagement -CustomerName 'Contoso' -Reference 'ENG-NEW' -OutputPath $missingParent

            Test-Path -LiteralPath $missingParent -PathType Container | Should -BeTrue
            Test-Path -LiteralPath $result.EngagementPath -PathType Container | Should -BeTrue
        }

        It 'Should refuse to overwrite an existing engagement folder' {
            $null = New-ZTAssessEngagement -CustomerName 'Contoso' -Reference 'ENG-DUP' -OutputPath $TestDrive

            { New-ZTAssessEngagement -CustomerName 'Contoso' -Reference 'ENG-DUP' -OutputPath $TestDrive -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*already exists*'
        }
    }

    Context 'When using -WhatIf' {
        It 'Should not create any folder or file' {
            $null = New-ZTAssessEngagement -CustomerName 'Whatif Co' -Reference 'ENG-WI' -OutputPath $TestDrive -WhatIf

            Test-Path -LiteralPath (Join-Path $TestDrive 'Whatif-Co-ENG-WI') | Should -BeFalse
        }
    }
}
