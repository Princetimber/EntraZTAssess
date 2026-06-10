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

Describe 'Invoke-ZTAssessCollectionSet' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:dscModuleName -CommandName Write-ToLog -MockWith { }
    }

    Context 'When all collectors succeed' {
        It 'Should persist snapshots, record timings, and report success' {
            InModuleScope -ModuleName $script:dscModuleName {
                $runPath = Join-Path $TestDrive 'run-ok'
                $null = New-Item -Path $runPath -ItemType Directory
                $manifest = New-ZTAssessRunManifest -ToolVersion '1.0.0'

                $specs = @(
                    @{ Name = 'alpha'; Fetch = { @([pscustomobject]@{ id = 1 }, [pscustomobject]@{ id = 2 }) } }
                    @{ Name = 'beta'; Fetch = { [pscustomobject]@{ id = 'single' } } }
                )

                $status = Invoke-ZTAssessCollectionSet -RunPath $runPath -Specs $specs -Manifest $manifest

                $status['alpha'].Success | Should -BeTrue
                $status['alpha'].RecordCount | Should -Be 2
                $status['beta'].Success | Should -BeTrue
                Test-Path (Join-Path $runPath 'Raw/alpha.json') | Should -BeTrue
                Test-Path (Join-Path $runPath 'Raw/beta.json') | Should -BeTrue
                $manifest.RecordCounts['alpha'] | Should -Be 2
            }
        }
    }

    Context 'When a collector fails' {
        It 'Should record the failure, warn, and continue with remaining collectors' {
            InModuleScope -ModuleName $script:dscModuleName {
                $runPath = Join-Path $TestDrive 'run-fail'
                $null = New-Item -Path $runPath -ItemType Directory
                $manifest = New-ZTAssessRunManifest -ToolVersion '1.0.0'

                $specs = @(
                    @{ Name = 'broken'; Fetch = { throw 'Response status code does not indicate success: 403 (Forbidden).' } }
                    @{ Name = 'working'; Fetch = { @([pscustomobject]@{ id = 1 }) } }
                )

                $status = Invoke-ZTAssessCollectionSet -RunPath $runPath -Specs $specs -Manifest $manifest -WarningAction SilentlyContinue

                $status['broken'].Success | Should -BeFalse
                $status['broken'].Error | Should -Match '403'
                Test-Path (Join-Path $runPath 'Raw/broken.json') | Should -BeFalse

                $status['working'].Success | Should -BeTrue
                Test-Path (Join-Path $runPath 'Raw/working.json') | Should -BeTrue

                $manifest.Warnings.Count | Should -Be 1
            }
        }
    }
}
