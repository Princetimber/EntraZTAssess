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

Describe 'Get-ZTAssessHttpStatusCode' -Tag 'Unit' {

    Context 'When the exception exposes a typed response' {
        It 'Should read the status code from the Response property' {
            InModuleScope -ModuleName $script:dscModuleName {
                $exception = [System.Exception]::new('Request failed.')
                $response = [pscustomobject]@{ StatusCode = 429 }
                $exception | Add-Member -NotePropertyName Response -NotePropertyValue $response

                $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'TestError', 'InvalidOperation', $null)

                Get-ZTAssessHttpStatusCode -ErrorRecord $errorRecord | Should -Be 429
            }
        }

        It 'Should read a StatusCode property directly on the exception' {
            InModuleScope -ModuleName $script:dscModuleName {
                $exception = [System.Exception]::new('Request failed.')
                $exception | Add-Member -NotePropertyName StatusCode -NotePropertyValue 503

                $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'TestError', 'InvalidOperation', $null)

                Get-ZTAssessHttpStatusCode -ErrorRecord $errorRecord | Should -Be 503
            }
        }
    }

    Context 'When only the message contains the status code' {
        It 'Should parse 429 from the message text' {
            InModuleScope -ModuleName $script:dscModuleName {
                $exception = [System.Exception]::new('Response status code does not indicate success: 429 (Too Many Requests).')
                $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'TestError', 'InvalidOperation', $null)

                Get-ZTAssessHttpStatusCode -ErrorRecord $errorRecord | Should -Be 429
            }
        }

        It 'Should parse 403 from the message text' {
            InModuleScope -ModuleName $script:dscModuleName {
                $exception = [System.Exception]::new('Response status code does not indicate success: 403 (Forbidden).')
                $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'TestError', 'InvalidOperation', $null)

                Get-ZTAssessHttpStatusCode -ErrorRecord $errorRecord | Should -Be 403
            }
        }
    }

    Context 'When no status code is available' {
        It 'Should return 0' {
            InModuleScope -ModuleName $script:dscModuleName {
                $exception = [System.Exception]::new('Something else went wrong entirely.')
                $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'TestError', 'InvalidOperation', $null)

                Get-ZTAssessHttpStatusCode -ErrorRecord $errorRecord | Should -Be 0
            }
        }
    }
}
