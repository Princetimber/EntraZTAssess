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

Describe 'ConvertTo-ZTAssessNormalizedJsonObject' -Tag 'Unit' {

    It 'Should pass through primitive values unchanged' {
        InModuleScope -ModuleName $script:dscModuleName {
            ConvertTo-ZTAssessNormalizedJsonObject -InputObject 'text' | Should -Be 'text'
            ConvertTo-ZTAssessNormalizedJsonObject -InputObject 42 | Should -Be 42
            ConvertTo-ZTAssessNormalizedJsonObject -InputObject $null | Should -BeNullOrEmpty
        }
    }

    It 'Should convert a hashtable with no collisions into a pscustomobject' {
        InModuleScope -ModuleName $script:dscModuleName {
            $result = ConvertTo-ZTAssessNormalizedJsonObject -InputObject @{ Name = 'Contoso'; Enabled = $true }

            $result | Should -BeOfType [pscustomobject]
            $result.Name | Should -Be 'Contoso'
            $result.Enabled | Should -Be $true
        }
    }

    It 'Should resolve a case-insensitive sibling key collision by keeping the non-null value' {
        InModuleScope -ModuleName $script:dscModuleName {
            # A plain PowerShell hashtable/ordered-dictionary literal is
            # case-INsensitive, so it can't hold 'Value' and 'value' as
            # distinct keys - exactly what ConvertFrom-Json -AsHashtable can
            # do (it uses a case-sensitive comparer, which is the whole
            # reason Get-ZTAssessSnapshot falls back to it). Build a
            # case-sensitive dictionary here to reproduce that shape.
            $sourceHash = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
            $sourceHash['Name'] = 'Policy1'
            $sourceHash['Value'] = 'Real'
            $sourceHash['value'] = $null

            $result = ConvertTo-ZTAssessNormalizedJsonObject -InputObject $sourceHash

            $result | Should -BeOfType [pscustomobject]
            @($result.PSObject.Properties.Name) | Should -HaveCount 2
            $result.Value | Should -Be 'Real'
        }
    }

    It 'Should recurse into nested arrays of hashtables' {
        InModuleScope -ModuleName $script:dscModuleName {
            $result = ConvertTo-ZTAssessNormalizedJsonObject -InputObject @(
                @{ Name = 'a' }
                @{ Name = 'b' }
            )

            @($result).Count | Should -Be 2
            @($result)[0].Name | Should -Be 'a'
            @($result)[1].Name | Should -Be 'b'
        }
    }
}
