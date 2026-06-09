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

Describe 'Save-ZTAssessRunManifest' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:dscModuleName -CommandName Write-ToLog -MockWith { }
    }

    Context 'When persisting a valid manifest' {
        It 'Should write manifest.json into the run folder' {
            InModuleScope -ModuleName $script:dscModuleName {
                $runPath = Join-Path $TestDrive 'run-1'
                $null = New-Item -Path $runPath -ItemType Directory

                $manifest = New-ZTAssessRunManifest -ToolVersion '1.0.0' -AuthMode Delegated -TenantId 'tenant-1'

                $writtenPath = Save-ZTAssessRunManifest -Manifest $manifest -RunPath $runPath

                $writtenPath | Should -Be (Join-Path $runPath 'manifest.json')
                Test-Path -LiteralPath $writtenPath -PathType Leaf | Should -BeTrue
            }
        }

        It 'Should produce JSON that round-trips the key fields' {
            InModuleScope -ModuleName $script:dscModuleName {
                $runPath = Join-Path $TestDrive 'run-2'
                $null = New-Item -Path $runPath -ItemType Directory

                $manifest = New-ZTAssessRunManifest -ToolVersion '1.0.0' -AuthMode AppOnly -TenantId 'tenant-2' -Modules @('Identity', 'Devices')
                $manifest.RecordCollector('TestCollector', 3.2, 10)
                $manifest.Complete()

                $writtenPath = Save-ZTAssessRunManifest -Manifest $manifest -RunPath $runPath
                $roundTrip = Get-Content -LiteralPath $writtenPath -Raw | ConvertFrom-Json

                $roundTrip.ToolVersion | Should -Be '1.0.0'
                $roundTrip.AuthMode | Should -Be 'AppOnly'
                $roundTrip.TenantId | Should -Be 'tenant-2'
                @($roundTrip.Modules) | Should -Contain 'Devices'
                $roundTrip.CollectorTimings.TestCollector | Should -Be 3.2
            }
        }
    }

    Context 'When inputs are invalid' {
        It 'Should throw when the manifest fails validation' {
            InModuleScope -ModuleName $script:dscModuleName {
                $manifest = [ZTAssessRunManifest]::new()   # no ToolVersion

                $runPath = Join-Path $TestDrive 'run-3'
                $null = New-Item -Path $runPath -ItemType Directory

                { Save-ZTAssessRunManifest -Manifest $manifest -RunPath $runPath } |
                    Should -Throw -ExpectedMessage '*invalid*'
            }
        }

        It 'Should throw when the run path does not exist' {
            InModuleScope -ModuleName $script:dscModuleName {
                $manifest = New-ZTAssessRunManifest -ToolVersion '1.0.0'

                { Save-ZTAssessRunManifest -Manifest $manifest -RunPath (Join-Path $TestDrive 'missing-run') } |
                    Should -Throw -ExpectedMessage '*does not exist*'
            }
        }
    }

    Context 'When using -WhatIf' {
        It 'Should not write any file' {
            InModuleScope -ModuleName $script:dscModuleName {
                $runPath = Join-Path $TestDrive 'run-4'
                $null = New-Item -Path $runPath -ItemType Directory

                $manifest = New-ZTAssessRunManifest -ToolVersion '1.0.0'

                $null = Save-ZTAssessRunManifest -Manifest $manifest -RunPath $runPath -WhatIf

                Test-Path -LiteralPath (Join-Path $runPath 'manifest.json') | Should -BeFalse
            }
        }
    }
}
