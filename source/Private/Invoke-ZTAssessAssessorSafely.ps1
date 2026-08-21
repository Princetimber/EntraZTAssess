#Requires -Version 7.0

# Runs one module's assessor (or a small group of related assessor/snapshot
# calls) inside a try/catch, so an exception from a single module - a
# corrupt/unparseable snapshot, an unexpected data shape, anything - degrades
# just that module to zero findings instead of aborting the entire assessment
# run for every other module too. Mirrors the graceful-degradation pattern
# Invoke-ZTAssessCollectionSet already applies to collector failures.
function Invoke-ZTAssessAssessorSafely {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ModuleName,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory)]
        $Manifest
    )

    try {
        return @(& $ScriptBlock)
    } catch {
        $reason = $_.Exception.Message
        Write-ToLog -Message "Assessor for module '$ModuleName' failed; its checks will be reported as NotAssessed. Error: $reason" -Level WARN -NoConsole
        Write-Warning "Assessor for module '$ModuleName' failed; its checks will be reported as NotAssessed."
        $Manifest.AddWarning("Assessor for module '$ModuleName' failed: $reason")
        return @()
    }
}
