#Requires -Version 7.0

# Loads and caches the module configuration data files (settings.psd1 and
# permissions.psd1) from the Settings folder. The cache is module-scoped so
# the files are read once per session. Use -Force to reload after an
# engagement-level override has been applied.
function Get-ZTAssessConfiguration {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [ValidateSet('Settings', 'Permissions')]
        [string]$Name = 'Settings',

        [Parameter()]
        [switch]$Force
    )

    if (-not $script:ZTAssessConfigurationCache) {
        $script:ZTAssessConfigurationCache = @{}
    }

    if ($Force -or -not $script:ZTAssessConfigurationCache.ContainsKey($Name)) {
        $fileName = switch ($Name) {
            'Settings' { 'settings.psd1' }
            'Permissions' { 'permissions.psd1' }
        }

        # Resolve the module base folder. Works for both the dev-time layout
        # (source/) and the built module (Settings copied beside the psm1).
        # $script:ZTAssessModuleRoot may be pre-set by tests to redirect.
        $moduleRoot = $script:ZTAssessModuleRoot
        if (-not $moduleRoot) {
            $moduleRoot = $MyInvocation.MyCommand.Module.ModuleBase
        }
        if (-not $moduleRoot) {
            throw 'Unable to resolve the module base path for configuration loading.'
        }

        $settingsRoot = Join-Path -Path $moduleRoot -ChildPath 'Settings'
        $filePath = Join-Path -Path $settingsRoot -ChildPath $fileName

        if (-not (Test-Path -LiteralPath $filePath)) {
            throw "Configuration file not found: $filePath. The module installation appears incomplete."
        }

        try {
            $script:ZTAssessConfigurationCache[$Name] = Import-PowerShellDataFile -LiteralPath $filePath -ErrorAction Stop
        }
        catch {
            throw "Failed to parse configuration file '$filePath': $($_.Exception.Message)"
        }
    }

    return $script:ZTAssessConfigurationCache[$Name]
}
