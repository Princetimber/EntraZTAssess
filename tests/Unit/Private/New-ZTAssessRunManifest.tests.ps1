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

Describe 'New-ZTAssessRunManifest' -Tag 'Unit' {

    Context 'When creating a manifest' {
        It 'Should populate the supplied values' {
            InModuleScope -ModuleName $script:dscModuleName {
                $manifest = New-ZTAssessRunManifest -ToolVersion '1.0.0' -AuthMode Delegated `
                    -Account 'consultant@contoso.com' -TenantId 'tenant-1' `
                    -GrantedScopes @('Directory.Read.All') -Modules @('Identity')

                $manifest.ToolVersion | Should -Be '1.0.0'
                $manifest.AuthMode | Should -Be 'Delegated'
                $manifest.Account | Should -Be 'consultant@contoso.com'
                $manifest.TenantId | Should -Be 'tenant-1'
                $manifest.GrantedScopes | Should -Contain 'Directory.Read.All'
                $manifest.Modules | Should -Contain 'Identity'
            }
        }

        It 'Should record the running PowerShell version and a UTC start time' {
            InModuleScope -ModuleName $script:dscModuleName {
                $before = [datetime]::UtcNow.AddSeconds(-5)
                $manifest = New-ZTAssessRunManifest -ToolVersion '1.0.0'

                $manifest.PSVersion | Should -Be $PSVersionTable.PSVersion.ToString()
                $manifest.StartTime | Should -BeGreaterThan $before
            }
        }

        It 'Should default the check library version to the tool version' {
            InModuleScope -ModuleName $script:dscModuleName {
                $manifest = New-ZTAssessRunManifest -ToolVersion '1.2.3'

                $manifest.CheckLibraryVersion | Should -Be '1.2.3'
            }
        }

        It 'Should reject an invalid auth mode' {
            InModuleScope -ModuleName $script:dscModuleName {
                { New-ZTAssessRunManifest -ToolVersion '1.0.0' -AuthMode 'Password' } | Should -Throw
            }
        }
    }

    Context 'When using the manifest helper methods' {
        It 'Should record collector timings and counts' {
            InModuleScope -ModuleName $script:dscModuleName {
                $manifest = New-ZTAssessRunManifest -ToolVersion '1.0.0'

                $manifest.RecordCollector('Get-ZTAssessRawUsers', 12.5, 250)

                $manifest.CollectorTimings['Get-ZTAssessRawUsers'] | Should -Be 12.5
                $manifest.RecordCounts['Get-ZTAssessRawUsers'] | Should -Be 250
            }
        }

        It 'Should accumulate warnings' {
            InModuleScope -ModuleName $script:dscModuleName {
                $manifest = New-ZTAssessRunManifest -ToolVersion '1.0.0'

                $manifest.AddWarning('Scope X missing')
                $manifest.AddWarning('Licence Y absent')

                $manifest.Warnings.Count | Should -Be 2
            }
        }

        It 'Should set the end time when completed' {
            InModuleScope -ModuleName $script:dscModuleName {
                $manifest = New-ZTAssessRunManifest -ToolVersion '1.0.0'

                $manifest.Complete()

                $manifest.EndTime | Should -BeGreaterOrEqual $manifest.StartTime
            }
        }

        It 'Should validate cleanly when well formed' {
            InModuleScope -ModuleName $script:dscModuleName {
                $manifest = New-ZTAssessRunManifest -ToolVersion '1.0.0'

                $manifest.Validate() | Should -BeNullOrEmpty
            }
        }
    }
}
