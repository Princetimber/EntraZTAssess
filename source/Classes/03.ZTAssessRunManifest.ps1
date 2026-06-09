#Requires -Version 7.0

<#
    ZTAssessRunManifest

    Evidence-chain anchor for a single assessment run. Records what was
    executed, with which identity and scopes, when, and with what results.
    Persisted as manifest.json in the run folder and referenced by all
    reports. Must never contain tokens, secrets, or raw payloads.
#>
class ZTAssessRunManifest {
    [string] $ToolVersion
    [string] $CheckLibraryVersion
    [string] $PSVersion
    [string] $AuthMode
    [string] $Account
    [string] $TenantId
    [string] $Environment
    [string[]] $GrantedScopes
    [string[]] $MissingScopes
    [string[]] $Modules
    [datetime] $StartTime
    [datetime] $EndTime
    [hashtable] $CollectorTimings
    [hashtable] $RecordCounts
    [string[]] $Warnings

    static [string[]] $ValidAuthModes = @('Delegated', 'AppOnly', 'DeviceCode', 'Unknown')

    ZTAssessRunManifest() {
        $this.GrantedScopes = @()
        $this.MissingScopes = @()
        $this.Modules = @()
        $this.CollectorTimings = @{}
        $this.RecordCounts = @{}
        $this.Warnings = @()
        $this.AuthMode = 'Unknown'
        $this.StartTime = [datetime]::UtcNow
    }

    [void] AddWarning([string] $warning) {
        $this.Warnings += $warning
    }

    [void] RecordCollector([string] $collectorName, [double] $durationSeconds, [int] $recordCount) {
        $this.CollectorTimings[$collectorName] = $durationSeconds
        $this.RecordCounts[$collectorName] = $recordCount
    }

    [void] Complete() {
        $this.EndTime = [datetime]::UtcNow
    }

    # Returns a list of validation problems; empty list means the manifest is valid.
    [string[]] Validate() {
        $problems = [System.Collections.Generic.List[string]]::new()

        if ([string]::IsNullOrWhiteSpace($this.ToolVersion)) {
            $problems.Add('ToolVersion is required.')
        }

        if ($this.AuthMode -notin [ZTAssessRunManifest]::ValidAuthModes) {
            $problems.Add("AuthMode '$($this.AuthMode)' is not one of: $([ZTAssessRunManifest]::ValidAuthModes -join ', ').")
        }

        return $problems.ToArray()
    }

    [string] ToString() {
        return ('Run {0} ({1} module(s), tenant {2})' -f $this.StartTime.ToString('yyyyMMdd-HHmmss'), $this.Modules.Count, $this.TenantId)
    }
}
