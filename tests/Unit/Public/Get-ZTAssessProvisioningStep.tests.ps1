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

Describe 'Get-ZTAssessProvisioningStep' -Tag 'Unit' {

    It 'Should emit an ordered set of provisioning steps' {
        $steps = Get-ZTAssessProvisioningStep
        $steps.Count | Should -BeGreaterOrEqual 5
        $steps[0].PSObject.TypeNames | Should -Contain 'ZTAssess.ProvisioningStep'
        ($steps | ForEach-Object Step) | Should -Be (1..$steps.Count)
        ($steps.Command -join "`n") | Should -Match 'Import-Module .*EntraZTAssess\.Provisioning'
        ($steps.Command -join "`n") | Should -Match 'New-ZTAssessCertificate'
        ($steps.Command -join "`n") | Should -Match 'New-ZTAssessAppRegistration'
    }

    It 'Should tailor the app-registration and connect commands to -Modules' {
        $steps = Get-ZTAssessProvisioningStep -Modules Identity, Devices
        ($steps.Command -join "`n") | Should -Match '-Modules Identity, Devices'
    }

    It 'Should throw on an unknown module name' {
        { Get-ZTAssessProvisioningStep -Modules 'NoSuchModule' } | Should -Throw
    }
}
