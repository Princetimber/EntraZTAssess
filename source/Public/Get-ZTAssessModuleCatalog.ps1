#Requires -Version 7.0

function Get-ZTAssessModuleCatalog {
    <#
    .SYNOPSIS
    Lists the assessment modules available in the EntraZTAssess toolkit.

    .DESCRIPTION
    Returns the catalogue of assessment modules defined in permissions.psd1,
    including each module's description, the least-privilege Microsoft Graph
    scopes it requires, and whether it is always included or optional. Use
    this to decide which modules to enable for an engagement and to brief
    the customer on the permissions each module needs.

    .PARAMETER Name
    One or more module names to filter the catalogue by. Wildcards are not
    supported; names are matched exactly and case-insensitively. When
    omitted, every module in the catalogue is returned.

    .EXAMPLE
    Get-ZTAssessModuleCatalog

    Returns every assessment module with its description and required scopes.

    .EXAMPLE
    Get-ZTAssessModuleCatalog -Name Identity, Devices

    Returns the catalogue entries for the Identity and Devices modules only.

    .OUTPUTS
    PSCustomObject
    One object per module with properties: Name, Description, Scopes,
    AlwaysIncluded, Optional.

    .NOTES
    The catalogue is loaded from Settings/permissions.psd1 and cached for
    the session.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name
    )

    try {
        $catalogue = (Get-ZTAssessConfiguration -Name Permissions).Modules
    }
    catch {
        Write-Error -Message "Failed to load the module catalogue: $($_.Exception.Message)" -Category ResourceUnavailable -ErrorAction Stop
    }

    if ($Name) {
        $unknown = $Name | Where-Object { -not $catalogue.ContainsKey($_) }
        if ($unknown) {
            $available = ($catalogue.Keys | Sort-Object) -join ', '
            Write-Error -Message "Unknown module name(s): $($unknown -join ', '). Available modules: $available" -Category InvalidArgument -ErrorAction Stop
        }
    }

    $selectedKeys = if ($Name) { $Name } else { $catalogue.Keys | Sort-Object }

    foreach ($moduleKey in $selectedKeys) {
        $entry = $catalogue[$moduleKey]
        [pscustomobject]@{
            PSTypeName     = 'ZTAssess.ModuleCatalogEntry'
            Name           = $moduleKey
            Description    = $entry.Description
            Scopes         = @($entry.Scopes)
            AlwaysIncluded = [bool]$entry.AlwaysIncluded
            Optional       = [bool]$entry.Optional
        }
    }
}
