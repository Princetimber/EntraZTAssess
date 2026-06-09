#Requires -Version 7.0

BeforeAll {
    $script:dscModuleName = 'Get-EntraZTAssess'

    Import-Module -Name $script:dscModuleName
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Protect-ZTAssessData' -Tag 'Unit' {

    Context 'When the object contains denylisted properties' {
        It 'Should redact a top-level secret property' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                $data = [pscustomobject]@{
                    displayName = 'My App'
                    secretText  = 'super-secret-value'
                }
                Protect-ZTAssessData -InputObject $data
            }

            $result.displayName | Should -Be 'My App'
            $result.secretText | Should -Be '***REDACTED***'
        }

        It 'Should redact nested denylisted properties' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                $data = [pscustomobject]@{
                    app = [pscustomobject]@{
                        passwordProfile = [pscustomobject]@{ forceChange = $true }
                        owner           = 'someone@contoso.com'
                    }
                }
                Protect-ZTAssessData -InputObject $data
            }

            $result.app.passwordProfile | Should -Be '***REDACTED***'
            $result.app.owner | Should -Be 'someone@contoso.com'
        }

        It 'Should redact denylisted properties inside arrays' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                $data = @(
                    [pscustomobject]@{ id = '1'; token = 'abc' }
                    [pscustomobject]@{ id = '2'; token = 'def' }
                )
                Protect-ZTAssessData -InputObject $data
            }

            $result.Count | Should -Be 2
            $result[0].token | Should -Be '***REDACTED***'
            $result[1].token | Should -Be '***REDACTED***'
            $result[0].id | Should -Be '1'
        }

        It 'Should redact denylisted keys in hashtables case-insensitively' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                $data = @{
                    DisplayName = 'thing'
                    PASSWORD    = 'oops'
                }
                Protect-ZTAssessData -InputObject $data
            }

            $result['PASSWORD'] | Should -Be '***REDACTED***'
            $result['DisplayName'] | Should -Be 'thing'
        }

        It 'Should honour dotted denylist entries by their leaf name' {
            # 'keyCredentials.key' in the denylist means any 'key' property is redacted.
            $result = InModuleScope -ModuleName $script:dscModuleName {
                $data = [pscustomobject]@{
                    keyCredentials = @(
                        [pscustomobject]@{ keyId = 'kid-1'; key = 'AAAA' }
                    )
                }
                Protect-ZTAssessData -InputObject $data
            }

            $result.keyCredentials[0].key | Should -Be '***REDACTED***'
            $result.keyCredentials[0].keyId | Should -Be 'kid-1'
        }
    }

    Context 'When the object is clean' {
        It 'Should return an equivalent object untouched' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                $data = [pscustomobject]@{
                    id          = 'abc'
                    displayName = 'Safe Object'
                    enabled     = $true
                    count       = 42
                }
                Protect-ZTAssessData -InputObject $data
            }

            $result.id | Should -Be 'abc'
            $result.displayName | Should -Be 'Safe Object'
            $result.enabled | Should -BeTrue
            $result.count | Should -Be 42
        }

        It 'Should pass through null input' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                Protect-ZTAssessData -InputObject $null
            }

            $result | Should -BeNullOrEmpty
        }
    }

    Context 'When the original object is inspected afterwards' {
        It 'Should not modify the input object' {
            InModuleScope -ModuleName $script:dscModuleName {
                $data = [pscustomobject]@{ secretText = 'original-value' }

                $null = Protect-ZTAssessData -InputObject $data

                $data.secretText | Should -Be 'original-value'
            }
        }
    }

    Context 'When a custom denylist is supplied' {
        It 'Should use the custom denylist instead of the configured one' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                $data = [pscustomobject]@{
                    customSecret = 'hide-me'
                    secretText   = 'normally-redacted'
                }
                Protect-ZTAssessData -InputObject $data -Denylist @('customSecret')
            }

            $result.customSecret | Should -Be '***REDACTED***'
            $result.secretText | Should -Be 'normally-redacted'
        }
    }
}
