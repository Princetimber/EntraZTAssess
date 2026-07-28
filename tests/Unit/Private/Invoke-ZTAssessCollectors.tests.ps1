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

Describe 'Assessment collectors' -Tag 'Unit' {

    # Every domain collector is a declarative spec table that funnels its Graph
    # reads through Invoke-ZTAssessGraphRequest and persists snapshots via the
    # shared Invoke-ZTAssessCollectionSet. Exercising each end-to-end against a
    # mocked read-only wrapper proves the spec tables fetch and persist without
    # a live tenant.
    $script:collectors = @(
        'Invoke-ZTAssessCoreCollection'
        'Invoke-ZTAssessIdentityCollection'
        'Invoke-ZTAssessConditionalAccessCollection'
        'Invoke-ZTAssessPrivilegedAccessCollection'
        'Invoke-ZTAssessDeviceCollection'
        'Invoke-ZTAssessGovernanceCollection'
        'Invoke-ZTAssessApplicationCollection'
        'Invoke-ZTAssessHybridCollection'
        'Invoke-ZTAssessMonitoringCollection'
    )

    It 'Should fetch via the read-only wrapper and persist snapshots: <_>' -ForEach $script:collectors {
        $collector = $_
        InModuleScope -ModuleName $script:dscModuleName -Parameters @{ Collector = $collector } {
            param($Collector)

            Mock Write-ToLog { }
            # Canned read-only response; the extra properties satisfy the few
            # specs that post-process the wrapper result (e.g. `.settings`).
            Mock Invoke-ZTAssessGraphRequest { @([pscustomobject]@{ id = 'x'; settings = @{} }) }

            $runPath = Join-Path $TestDrive $Collector
            $null = New-Item -Path $runPath -ItemType Directory -Force
            $manifest = New-ZTAssessRunManifest -ToolVersion '1.0.0'

            $status = & $Collector -RunPath $runPath -Manifest $manifest -WarningAction SilentlyContinue

            $status | Should -Not -BeNullOrEmpty
            (Get-ChildItem -Path (Join-Path $runPath 'Raw') -Filter '*.json').Count | Should -BeGreaterThan 0
            Should -Invoke Invoke-ZTAssessGraphRequest
        }
    }
}
