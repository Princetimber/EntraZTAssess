#Requires -Version 7.0

BeforeAll {
    $script:dscModuleName = 'Get-EntraZTAssess'

    Import-Module -Name $script:dscModuleName
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Get-ZTAssessRequiredPermission' -Tag 'Unit' {

    Context 'When computing scopes for selected modules' {
        It 'Should always include the Core module scopes' {
            $result = Get-ZTAssessRequiredPermission -Modules Identity

            $result.Scope | Should -Contain 'Organization.Read.All'
            $result.Scope | Should -Contain 'Directory.Read.All'
        }

        It 'Should include the scopes of every selected module' {
            $result = Get-ZTAssessRequiredPermission -Modules Identity, Devices

            $result.Scope | Should -Contain 'UserAuthenticationMethod.Read.All'
            $result.Scope | Should -Contain 'DeviceManagementManagedDevices.Read.All'
        }

        It 'Should not include scopes of unselected modules' {
            $result = Get-ZTAssessRequiredPermission -Modules Identity

            $result.Scope | Should -Not -Contain 'DeviceManagementManagedDevices.Read.All'
        }

        It 'Should de-duplicate scopes shared between modules and record both requirers' {
            # Identity and ConditionalAccess both require Policy.Read.All
            $result = Get-ZTAssessRequiredPermission -Modules Identity, ConditionalAccess

            $policyScope = @($result | Where-Object Scope -eq 'Policy.Read.All')
            $policyScope.Count | Should -Be 1
            $policyScope[0].RequiredBy | Should -Contain 'Identity'
            $policyScope[0].RequiredBy | Should -Contain 'ConditionalAccess'
        }

        It 'Should throw for unknown module names' {
            { Get-ZTAssessRequiredPermission -Modules 'NoSuchModule' -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*Unknown module name*'
        }
    }

    Context 'When requesting a plain scope list' {
        It 'Should return a sorted, de-duplicated string array' {
            $result = Get-ZTAssessRequiredPermission -Modules Identity, ConditionalAccess -AsScopeList

            $result | Should -BeOfType [string]
            ($result | Select-Object -Unique).Count | Should -Be $result.Count
            $sorted = @($result | Sort-Object)
            for ($i = 0; $i -lt $result.Count; $i++) {
                $result[$i] | Should -Be $sorted[$i]
            }
        }
    }
}
