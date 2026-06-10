#Requires -Version 7.0

# Loads and caches the declarative check definition library from the Checks
# folder. Each check is a PSD1 file named <CheckId>.psd1 beneath a domain
# subfolder. Returns all checks, one domain, or a single check by ID.
function Get-ZTAssessCheckDefinition {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$CheckId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Domain,

        [Parameter()]
        [switch]$Force
    )

    if ($Force -or -not $script:ZTAssessCheckCache) {
        $moduleRoot = $script:ZTAssessModuleRoot
        if (-not $moduleRoot) {
            $moduleRoot = $MyInvocation.MyCommand.Module.ModuleBase
        }
        if (-not $moduleRoot) {
            throw 'Unable to resolve the module base path for check definition loading.'
        }

        $checksRoot = Join-Path -Path $moduleRoot -ChildPath 'Checks'
        if (-not (Test-Path -LiteralPath $checksRoot)) {
            throw "Check library folder not found: $checksRoot. The module installation appears incomplete."
        }

        $cache = @{}
        foreach ($file in (Get-ChildItem -Path $checksRoot -Recurse -Filter '*.psd1')) {
            try {
                $definition = Import-PowerShellDataFile -LiteralPath $file.FullName -ErrorAction Stop
            }
            catch {
                throw "Failed to parse check definition '$($file.FullName)': $($_.Exception.Message)"
            }

            foreach ($requiredKey in @('CheckId', 'Domain', 'Title', 'DefaultSeverity', 'MaturityWeight')) {
                if (-not $definition.ContainsKey($requiredKey)) {
                    throw "Check definition '$($file.FullName)' is missing required key '$requiredKey'."
                }
            }

            $cache[$definition.CheckId] = $definition
        }

        $script:ZTAssessCheckCache = $cache
    }

    if ($CheckId) {
        if (-not $script:ZTAssessCheckCache.ContainsKey($CheckId)) {
            throw "Unknown check ID: $CheckId. The check library contains $($script:ZTAssessCheckCache.Count) checks."
        }
        return $script:ZTAssessCheckCache[$CheckId]
    }

    $selected = $script:ZTAssessCheckCache.Values
    if ($Domain) {
        $selected = $selected | Where-Object { $_.Domain -eq $Domain }
    }

    # Return as a hashtable keyed by CheckId for deterministic consumption.
    $result = @{}
    foreach ($entry in $selected) {
        $result[$entry.CheckId] = $entry
    }
    return $result
}
