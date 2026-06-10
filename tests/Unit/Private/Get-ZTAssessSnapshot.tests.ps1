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
}
