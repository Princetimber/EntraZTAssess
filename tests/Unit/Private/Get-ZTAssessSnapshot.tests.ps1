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

Describe 'Get-ZTAssessSnapshot' -Tag 'Unit' {

    Context 'When the snapshot exists' {
        It 'Should round-trip data written by Save-ZTAssessSnapshot' {
            InModuleScope -ModuleName $script:dscModuleName {
                Mock Write-ToLog { }
                $runPath = Join-Path $TestDrive 'run-1'
                $null = New-Item -Path $runPath -ItemType Directory

                $null = Save-ZTAssessSnapshot -Data @([pscustomobject]@{ id = 'a' }, [pscustomobject]@{ id = 'b' }) -RunPath $runPath -Name 'things'
                $result = Get-ZTAssessSnapshot -RunPath $runPath -Name 'things'

                @($result).Count | Should -Be 2
                @($result)[0].id | Should -Be 'a'
            }
        }
    }

    Context 'When the snapshot does not exist' {
        It 'Should return null rather than throwing' {
            InModuleScope -ModuleName $script:dscModuleName {
                $runPath = Join-Path $TestDrive 'run-2'
                $null = New-Item -Path $runPath -ItemType Directory

                Get-ZTAssessSnapshot -RunPath $runPath -Name 'missing' | Should -BeNullOrEmpty
            }
        }
    }

    Context 'When the snapshot contains JSON null' {
        It 'Should return null' {
            InModuleScope -ModuleName $script:dscModuleName {
                $runPath = Join-Path $TestDrive 'run-3'
                $null = New-Item -Path (Join-Path $runPath 'Raw') -ItemType Directory -Force
                Set-Content -Path (Join-Path $runPath 'Raw/empty.json') -Value 'null'

                Get-ZTAssessSnapshot -RunPath $runPath -Name 'empty' | Should -BeNullOrEmpty
            }
        }
    }

    Context 'When the snapshot has sibling keys differing only by case' {
        It 'Should fall back to -AsHashtable and return the object instead of throwing' {
            # Regression test: some collected payloads (observed live against
            # Get-DlpCompliancePolicy via the EXO/IPPS REST connection) carry
            # a 'value' property alongside a 'Value' property at the same
            # object level - legal JSON, but ConvertFrom-Json's default
            # case-insensitive PSCustomObject mode throws
            # "contains keys with different casing" reading it back.
            InModuleScope -ModuleName $script:dscModuleName {
                $runPath = Join-Path $TestDrive 'run-4'
                $null = New-Item -Path (Join-Path $runPath 'Raw') -ItemType Directory -Force
                Set-Content -Path (Join-Path $runPath 'Raw/casing.json') -Value '[{"Name":"Policy1","Value":"Real","value":"Shadow"}]'

                $result = Get-ZTAssessSnapshot -RunPath $runPath -Name 'casing'

                @($result).Count | Should -Be 1
                @($result)[0].Name | Should -Be 'Policy1'
            }
        }
    }

    Context 'When the snapshot is genuinely corrupt (not a casing collision)' {
        It 'Should still throw with an actionable message' {
            InModuleScope -ModuleName $script:dscModuleName {
                $runPath = Join-Path $TestDrive 'run-5'
                $null = New-Item -Path (Join-Path $runPath 'Raw') -ItemType Directory -Force
                Set-Content -Path (Join-Path $runPath 'Raw/broken.json') -Value '{ this is not valid json'

                { Get-ZTAssessSnapshot -RunPath $runPath -Name 'broken' } |
                    Should -Throw -ExpectedMessage "*Failed to read snapshot 'broken'*"
            }
        }
    }
}
