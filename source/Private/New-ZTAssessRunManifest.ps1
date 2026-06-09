#Requires -Version 7.0

# Factory for the run manifest object that anchors the evidence chain of an
# assessment run. Creates the in-memory object only; persistence is handled
# by Save-ZTAssessRunManifest.
function New-ZTAssessRunManifest {
    [CmdletBinding()]
    [OutputType([ZTAssessRunManifest])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Factory function creating an in-memory object only; no external state is changed.')]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ToolVersion,

        [Parameter()]
        [string]$CheckLibraryVersion = $ToolVersion,

        [Parameter()]
        [ValidateSet('Delegated', 'AppOnly', 'DeviceCode', 'Unknown')]
        [string]$AuthMode = 'Unknown',

        [Parameter()]
        [string]$Account,

        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [string]$Environment = 'Global',

        [Parameter()]
        [string[]]$GrantedScopes = @(),

        [Parameter()]
        [string[]]$MissingScopes = @(),

        [Parameter()]
        [string[]]$Modules = @()
    )

    $manifest = [ZTAssessRunManifest]::new()
    $manifest.ToolVersion = $ToolVersion
    $manifest.CheckLibraryVersion = $CheckLibraryVersion
    $manifest.PSVersion = $PSVersionTable.PSVersion.ToString()
    $manifest.AuthMode = $AuthMode
    $manifest.Account = $Account
    $manifest.TenantId = $TenantId
    $manifest.Environment = $Environment
    $manifest.GrantedScopes = $GrantedScopes
    $manifest.MissingScopes = $MissingScopes
    $manifest.Modules = $Modules

    return $manifest
}
