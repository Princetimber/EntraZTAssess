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

Describe 'Get-ZTAssessRetryDelay' -Tag 'Unit' {

    Context 'When the response carries typed RetryAfter headers' {
        It 'Should return the Delta total seconds' {
            InModuleScope -ModuleName $script:dscModuleName {
                $headers = [pscustomobject]@{
                    RetryAfter = [pscustomobject]@{ Delta = [timespan]::FromSeconds(11) }
                }
                $response = [pscustomobject]@{ Headers = $headers }
                $exception = [System.Exception]::new('Throttled.')
                $exception | Add-Member -NotePropertyName Response -NotePropertyValue $response

                $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'TestError', 'InvalidOperation', $null)

                Get-ZTAssessRetryDelay -ErrorRecord $errorRecord | Should -Be 11
            }
        }
    }

    Context 'When the response carries dictionary-style headers' {
        It 'Should parse the Retry-After value' {
            InModuleScope -ModuleName $script:dscModuleName {
                $response = [pscustomobject]@{ Headers = @{ 'Retry-After' = '7' } }
                $exception = [System.Exception]::new('Throttled.')
                $exception | Add-Member -NotePropertyName Response -NotePropertyValue $response

                $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'TestError', 'InvalidOperation', $null)

                Get-ZTAssessRetryDelay -ErrorRecord $errorRecord | Should -Be 7
            }
        }
    }

    Context 'When no Retry-After information exists' {
        It 'Should return 0 so callers use exponential backoff' {
            InModuleScope -ModuleName $script:dscModuleName {
                $exception = [System.Exception]::new('Throttled with no headers.')
                $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'TestError', 'InvalidOperation', $null)

                Get-ZTAssessRetryDelay -ErrorRecord $errorRecord | Should -Be 0
            }
        }
    }
}
