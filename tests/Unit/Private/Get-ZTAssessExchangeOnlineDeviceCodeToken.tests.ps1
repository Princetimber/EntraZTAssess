#Requires -Version 7.0

BeforeAll {
    $script:dscModuleName = 'Get-EntraZTAssess'

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

Describe 'Get-ZTAssessExchangeOnlineDeviceCodeToken' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:dscModuleName -CommandName Write-ToLog -MockWith { }
        Mock -ModuleName $script:dscModuleName -CommandName Start-Sleep -MockWith { }
    }

    It 'Should return the access token once the device code is authorized' {
        InModuleScope -ModuleName $script:dscModuleName {
            Mock -CommandName Invoke-RestMethod -ParameterFilter { $Uri -like '*devicecode*' } -MockWith {
                [pscustomobject]@{
                    device_code = 'device-1'
                    user_code   = 'ABCD-1234'
                    message     = 'To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code ABCD-1234 to authenticate.'
                    interval    = 1
                    expires_in  = 60
                }
            }

            $script:pollCount = 0
            Mock -CommandName Invoke-RestMethod -ParameterFilter { $Uri -like '*/token' } -MockWith {
                $script:pollCount++
                if ($script:pollCount -eq 1) {
                    $errorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":"authorization_pending"}')
                    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new('pending'), 'Pending', 'NotSpecified', $null)
                    $errorRecord.ErrorDetails = $errorDetails
                    Write-Error -ErrorRecord $errorRecord -ErrorAction Stop
                } else {
                    [pscustomobject]@{ access_token = 'token-xyz' }
                }
            }

            $result = Get-ZTAssessExchangeOnlineDeviceCodeToken -TenantId 'contoso.onmicrosoft.com' -ClientId 'client-1' -Scope 'https://outlook.office365.com/.default'

            $result | Should -Be 'token-xyz'
            Should -Invoke Invoke-RestMethod -ParameterFilter { $Uri -like '*/token' } -Times 2 -Exactly
        }
    }

    It 'Should throw an actionable error when the user declines or the code expires' {
        InModuleScope -ModuleName $script:dscModuleName {
            Mock -CommandName Invoke-RestMethod -ParameterFilter { $Uri -like '*devicecode*' } -MockWith {
                [pscustomobject]@{
                    device_code = 'device-2'
                    user_code   = 'EFGH-5678'
                    message     = 'To sign in...'
                    interval    = 1
                    expires_in  = 60
                }
            }

            Mock -CommandName Invoke-RestMethod -ParameterFilter { $Uri -like '*/token' } -MockWith {
                $errorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":"authorization_declined"}')
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new('declined'), 'Declined', 'NotSpecified', $null)
                $errorRecord.ErrorDetails = $errorDetails
                Write-Error -ErrorRecord $errorRecord -ErrorAction Stop
            }

            { Get-ZTAssessExchangeOnlineDeviceCodeToken -TenantId 'contoso.onmicrosoft.com' -ClientId 'client-1' -Scope 'https://outlook.office365.com/.default' } |
                Should -Throw -ExpectedMessage '*authorization_declined*'
        }
    }

    It 'Should throw when starting the device-code request itself fails' {
        InModuleScope -ModuleName $script:dscModuleName {
            Mock -CommandName Invoke-RestMethod -ParameterFilter { $Uri -like '*devicecode*' } -MockWith {
                throw 'network unreachable'
            }

            { Get-ZTAssessExchangeOnlineDeviceCodeToken -TenantId 'contoso.onmicrosoft.com' -ClientId 'client-1' -Scope 'https://outlook.office365.com/.default' } |
                Should -Throw -ExpectedMessage '*Failed to start the Exchange Online device-code sign-in*'
        }
    }

    It 'Should fall back to configured settings when -ClientId and -Scope are omitted' {
        InModuleScope -ModuleName $script:dscModuleName {
            Mock -CommandName Invoke-RestMethod -ParameterFilter { $Uri -like '*devicecode*' } -MockWith {
                [pscustomobject]@{
                    device_code = 'device-3'
                    user_code   = 'IJKL-9012'
                    message     = 'To sign in...'
                    interval    = 1
                    expires_in  = 60
                }
            }
            Mock -CommandName Invoke-RestMethod -ParameterFilter { $Uri -like '*/token' } -MockWith {
                [pscustomobject]@{ access_token = 'token-default' }
            }

            $result = Get-ZTAssessExchangeOnlineDeviceCodeToken -TenantId 'contoso.onmicrosoft.com'

            $result | Should -Be 'token-default'
            Should -Invoke Invoke-RestMethod -ParameterFilter {
                $Uri -like '*devicecode*' -and $Body.client_id -eq 'fb78d390-0c51-40cd-8e17-fdbfab77341b'
            } -Times 1 -Exactly
        }
    }
}
