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

Describe 'Invoke-ZTAssessGraphRequest' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:dscModuleName -CommandName Write-ToLog -MockWith { }
        Mock -ModuleName $script:dscModuleName -CommandName Start-SleepWrapper -MockWith { }
    }

    Context 'When the response is a collection' {
        It 'Should return the items in the value property' {
            Mock -ModuleName $script:dscModuleName -CommandName Invoke-MgGraphRequestWrapper -MockWith {
                [pscustomobject]@{
                    value = @(
                        [pscustomobject]@{ id = '1' }
                        [pscustomobject]@{ id = '2' }
                    )
                }
            }

            $result = InModuleScope -ModuleName $script:dscModuleName {
                Invoke-ZTAssessGraphRequest -Uri '/v1.0/users'
            }

            $result.Count | Should -Be 2
            $result.id | Should -Contain '1'
            $result.id | Should -Contain '2'
        }
    }

    Context 'When the response is a single entity' {
        It 'Should return the entity itself' {
            Mock -ModuleName $script:dscModuleName -CommandName Invoke-MgGraphRequestWrapper -MockWith {
                [pscustomobject]@{ id = 'tenant-1'; displayName = 'Contoso' }
            }

            $result = InModuleScope -ModuleName $script:dscModuleName {
                Invoke-ZTAssessGraphRequest -Uri '/v1.0/organization/tenant-1'
            }

            $result.Count | Should -Be 1
            $result[0].displayName | Should -Be 'Contoso'
        }
    }

    Context 'When the response is paged' {
        BeforeEach {
            Mock -ModuleName $script:dscModuleName -CommandName Invoke-MgGraphRequestWrapper -MockWith {
                if ($Uri -like '*skiptoken*') {
                    [pscustomobject]@{
                        value = @([pscustomobject]@{ id = 'page2-item' })
                    }
                }
                else {
                    [pscustomobject]@{
                        'value'           = @([pscustomobject]@{ id = 'page1-item' })
                        '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?$skiptoken=abc'
                    }
                }
            }
        }

        It 'Should follow @odata.nextLink when -All is specified' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                Invoke-ZTAssessGraphRequest -Uri '/v1.0/users' -All
            }

            $result.Count | Should -Be 2
            $result.id | Should -Contain 'page1-item'
            $result.id | Should -Contain 'page2-item'
        }

        It 'Should fetch only the first page when -All is not specified' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                Invoke-ZTAssessGraphRequest -Uri '/v1.0/users'
            }

            $result.Count | Should -Be 1
            $result[0].id | Should -Be 'page1-item'

            Should -Invoke -ModuleName $script:dscModuleName -CommandName Invoke-MgGraphRequestWrapper -Times 1 -Exactly
        }
    }

    Context 'When the request is throttled (429)' {
        It 'Should retry and eventually succeed' {
            InModuleScope -ModuleName $script:dscModuleName {
                $script:ZTAssessTestCallCount = 0
            }

            Mock -ModuleName $script:dscModuleName -CommandName Invoke-MgGraphRequestWrapper -MockWith {
                $script:ZTAssessTestCallCount++
                if ($script:ZTAssessTestCallCount -le 2) {
                    throw 'Response status code does not indicate success: 429 (Too Many Requests).'
                }
                [pscustomobject]@{ value = @([pscustomobject]@{ id = 'recovered' }) }
            }

            $result = InModuleScope -ModuleName $script:dscModuleName {
                Invoke-ZTAssessGraphRequest -Uri '/v1.0/users'
            }

            $result[0].id | Should -Be 'recovered'
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Invoke-MgGraphRequestWrapper -Times 3 -Exactly
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Start-SleepWrapper -Times 2 -Exactly
        }

        It 'Should give up after the maximum retry count' {
            Mock -ModuleName $script:dscModuleName -CommandName Invoke-MgGraphRequestWrapper -MockWith {
                throw 'Response status code does not indicate success: 429 (Too Many Requests).'
            }

            {
                InModuleScope -ModuleName $script:dscModuleName {
                    Invoke-ZTAssessGraphRequest -Uri '/v1.0/users' -MaxRetryCount 2
                }
            } | Should -Throw

            # 1 initial attempt + 2 retries
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Invoke-MgGraphRequestWrapper -Times 3 -Exactly
        }
    }

    Context 'When the request fails with a transient server error (5xx)' {
        It 'Should retry on 503' {
            InModuleScope -ModuleName $script:dscModuleName {
                $script:ZTAssessTestCallCount = 0
            }

            Mock -ModuleName $script:dscModuleName -CommandName Invoke-MgGraphRequestWrapper -MockWith {
                $script:ZTAssessTestCallCount++
                if ($script:ZTAssessTestCallCount -le 1) {
                    throw 'Response status code does not indicate success: 503 (Service Unavailable).'
                }
                [pscustomobject]@{ value = @([pscustomobject]@{ id = 'after-503' }) }
            }

            $result = InModuleScope -ModuleName $script:dscModuleName {
                Invoke-ZTAssessGraphRequest -Uri '/v1.0/users'
            }

            $result[0].id | Should -Be 'after-503'
        }
    }

    Context 'When the request fails with a non-retryable error' {
        It 'Should throw immediately on 403 without retrying' {
            Mock -ModuleName $script:dscModuleName -CommandName Invoke-MgGraphRequestWrapper -MockWith {
                throw 'Response status code does not indicate success: 403 (Forbidden).'
            }

            {
                InModuleScope -ModuleName $script:dscModuleName {
                    Invoke-ZTAssessGraphRequest -Uri '/v1.0/users'
                }
            } | Should -Throw

            Should -Invoke -ModuleName $script:dscModuleName -CommandName Invoke-MgGraphRequestWrapper -Times 1 -Exactly
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Start-SleepWrapper -Times 0 -Exactly
        }
    }

    Context 'When the URI is invalid' {
        It 'Should reject URIs that are not absolute https or relative Graph paths' {
            {
                InModuleScope -ModuleName $script:dscModuleName {
                    Invoke-ZTAssessGraphRequest -Uri 'http://insecure.example.com/users'
                }
            } | Should -Throw
        }
    }
}
