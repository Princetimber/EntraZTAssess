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

Describe 'Get-ZTAssessConfiguration' -Tag 'Unit' {

    BeforeEach {
        InModuleScope -ModuleName $script:dscModuleName {
            $script:ZTAssessConfigurationCache = $null
            $script:ZTAssessModuleRoot = $null
        }
    }

    AfterAll {
        InModuleScope -ModuleName $script:dscModuleName {
            $script:ZTAssessConfigurationCache = $null
            $script:ZTAssessModuleRoot = $null
        }
    }

    Context 'When loading the shipped configuration' {
        It 'Should load the settings file with expected top-level keys' {
            $settings = InModuleScope -ModuleName $script:dscModuleName {
                Get-ZTAssessConfiguration -Name Settings
            }

            $settings | Should -BeOfType [hashtable]
            $settings.Thresholds | Should -Not -BeNullOrEmpty
            $settings.Graph | Should -Not -BeNullOrEmpty
            $settings.RedactionDenylist | Should -Not -BeNullOrEmpty
            $settings.MaturityBands | Should -Not -BeNullOrEmpty
            $settings.DomainWeights | Should -Not -BeNullOrEmpty
        }

        It 'Should load the permissions file with a module catalogue' {
            $permissions = InModuleScope -ModuleName $script:dscModuleName {
                Get-ZTAssessConfiguration -Name Permissions
            }

            $permissions.Modules | Should -Not -BeNullOrEmpty
            $permissions.Modules.Keys | Should -Contain 'Core'
        }

        It 'Should define six maturity bands covering 0 to 100' {
            $settings = InModuleScope -ModuleName $script:dscModuleName {
                Get-ZTAssessConfiguration -Name Settings
            }

            $bands = @($settings.MaturityBands)
            $bands.Count | Should -Be 6
            ($bands | Measure-Object -Property Minimum -Minimum).Minimum | Should -Be 0
            ($bands | Measure-Object -Property Maximum -Maximum).Maximum | Should -Be 100
            $bands.Level | Should -Contain 'Optimised'
        }
    }

    Context 'When the configuration is cached' {
        It 'Should read the file only once for repeated calls' {
            InModuleScope -ModuleName $script:dscModuleName {
                $first = Get-ZTAssessConfiguration -Name Settings
                $second = Get-ZTAssessConfiguration -Name Settings

                # Same cached instance, not a re-parsed copy.
                [object]::ReferenceEquals($first, $second) | Should -BeTrue
            }
        }

        It 'Should re-read the file when -Force is specified' {
            InModuleScope -ModuleName $script:dscModuleName {
                $first = Get-ZTAssessConfiguration -Name Settings
                $second = Get-ZTAssessConfiguration -Name Settings -Force

                [object]::ReferenceEquals($first, $second) | Should -BeFalse
            }
        }
    }

    Context 'When the module root is redirected (test override)' {
        It 'Should load configuration from the overridden root' {
            InModuleScope -ModuleName $script:dscModuleName {
                $fakeRoot = Join-Path $TestDrive 'FakeModule'
                $null = New-Item -Path (Join-Path $fakeRoot 'Settings') -ItemType Directory -Force
                Set-Content -Path (Join-Path $fakeRoot 'Settings/settings.psd1') -Value "@{ Thresholds = @{ Marker = 'overridden' } }"

                $script:ZTAssessModuleRoot = $fakeRoot

                $settings = Get-ZTAssessConfiguration -Name Settings -Force

                $settings.Thresholds.Marker | Should -Be 'overridden'
            }
        }

        It 'Should throw a clear error when the file is missing' {
            InModuleScope -ModuleName $script:dscModuleName {
                $script:ZTAssessModuleRoot = Join-Path $TestDrive 'EmptyRoot'
                $null = New-Item -Path $script:ZTAssessModuleRoot -ItemType Directory -Force

                { Get-ZTAssessConfiguration -Name Settings -Force } |
                    Should -Throw -ExpectedMessage '*Configuration file not found*'
            }
        }
    }
}
