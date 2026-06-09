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

Describe 'Save-ZTAssessSnapshot' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:dscModuleName -CommandName Write-ToLog -MockWith { }
    }

    Context 'When persisting a snapshot' {
        It 'Should create the Raw folder and write the named JSON file' {
            InModuleScope -ModuleName $script:dscModuleName {
                $runPath = Join-Path $TestDrive 'run-1'
                $null = New-Item -Path $runPath -ItemType Directory

                $data = @([pscustomobject]@{ id = '1'; displayName = 'User One' })

                $writtenPath = Save-ZTAssessSnapshot -Data $data -RunPath $runPath -Name 'users'

                $writtenPath | Should -Be (Join-Path $runPath 'Raw/users.json')
                Test-Path -LiteralPath $writtenPath -PathType Leaf | Should -BeTrue
            }
        }

        It 'Should redact denylisted properties before writing' {
            InModuleScope -ModuleName $script:dscModuleName {
                $runPath = Join-Path $TestDrive 'run-2'
                $null = New-Item -Path $runPath -ItemType Directory

                $data = [pscustomobject]@{
                    appId      = 'app-1'
                    secretText = 'do-not-persist'
                }

                $writtenPath = Save-ZTAssessSnapshot -Data $data -RunPath $runPath -Name 'apps'
                $raw = Get-Content -LiteralPath $writtenPath -Raw

                $raw | Should -Not -Match 'do-not-persist'
                $raw | Should -Match '\*\*\*REDACTED\*\*\*'
            }
        }

        It 'Should round-trip non-sensitive data faithfully' {
            InModuleScope -ModuleName $script:dscModuleName {
                $runPath = Join-Path $TestDrive 'run-3'
                $null = New-Item -Path $runPath -ItemType Directory

                $data = @(
                    [pscustomobject]@{ id = 'a'; enabled = $true }
                    [pscustomobject]@{ id = 'b'; enabled = $false }
                )

                $writtenPath = Save-ZTAssessSnapshot -Data $data -RunPath $runPath -Name 'devices'
                $roundTrip = Get-Content -LiteralPath $writtenPath -Raw | ConvertFrom-Json

                @($roundTrip).Count | Should -Be 2
                @($roundTrip)[0].id | Should -Be 'a'
                @($roundTrip)[1].enabled | Should -BeFalse
            }
        }
    }

    Context 'When inputs are invalid' {
        It 'Should reject snapshot names with unsafe characters' {
            InModuleScope -ModuleName $script:dscModuleName {
                $runPath = Join-Path $TestDrive 'run-4'
                $null = New-Item -Path $runPath -ItemType Directory

                { Save-ZTAssessSnapshot -Data @{} -RunPath $runPath -Name '../escape' } | Should -Throw
            }
        }

        It 'Should throw when the run path does not exist' {
            InModuleScope -ModuleName $script:dscModuleName {
                { Save-ZTAssessSnapshot -Data @{} -RunPath (Join-Path $TestDrive 'missing') -Name 'users' } |
                    Should -Throw -ExpectedMessage '*does not exist*'
            }
        }
    }

    Context 'When using -WhatIf' {
        It 'Should not write any file' {
            InModuleScope -ModuleName $script:dscModuleName {
                $runPath = Join-Path $TestDrive 'run-5'
                $null = New-Item -Path $runPath -ItemType Directory

                $null = Save-ZTAssessSnapshot -Data @{ id = 1 } -RunPath $runPath -Name 'whatif' -WhatIf

                Test-Path -LiteralPath (Join-Path $runPath 'Raw/whatif.json') | Should -BeFalse
            }
        }
    }
}
