#Requires -Version 7.0

# Shared collection runner. Executes a set of collection specifications,
# persisting each result as a redacted snapshot, timing every collector,
# and degrading gracefully: a failed collector records a warning and the
# dependent checks become NotAssessed rather than the run aborting.
#
# Each specification is a hashtable: @{ Name = 'users'; Fetch = { ... } }
# where Fetch is a script block returning the data to persist.
function Invoke-ZTAssessCollectionSet {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RunPath,

        [Parameter(Mandatory)]
        [hashtable[]]$Specs,

        [Parameter()]
        [ZTAssessRunManifest]$Manifest
    )

    $status = @{}

    foreach ($spec in $Specs) {
        $name = [string]$spec.Name
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            Write-ToLog -Message "Collecting '$name'..." -Level INFO -NoConsole
            $data = & $spec.Fetch
            $stopwatch.Stop()

            $recordCount = if ($null -eq $data) { 0 } elseif ($data -is [System.Collections.ICollection]) { $data.Count } else { 1 }

            $null = Save-ZTAssessSnapshot -Data $data -RunPath $RunPath -Name $name

            $status[$name] = @{
                Success         = $true
                RecordCount     = $recordCount
                DurationSeconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
                Error           = $null
            }

            if ($Manifest) {
                $Manifest.RecordCollector($name, $status[$name].DurationSeconds, $recordCount)
            }

            Write-ToLog -Message "Collected '$name': $recordCount record(s) in $($status[$name].DurationSeconds)s" -Level DEBUG -NoConsole
        }
        catch {
            $stopwatch.Stop()
            $reason = $_.Exception.Message

            $status[$name] = @{
                Success         = $false
                RecordCount     = 0
                DurationSeconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
                Error           = $reason
            }

            if ($Manifest) {
                $Manifest.AddWarning("Collector '$name' failed: $reason")
            }

            Write-ToLog -Message "Collector '$name' failed; dependent checks will be NotAssessed. Error: $reason" -Level WARN -NoConsole
            Write-Warning "Collector '$name' failed; dependent checks will be reported as NotAssessed."
        }
    }

    return $status
}
