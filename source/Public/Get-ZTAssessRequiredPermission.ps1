#Requires -Version 7.0

function Get-ZTAssessRequiredPermission {
    <#
    .SYNOPSIS
    Computes the least-privilege Microsoft Graph scopes for selected modules.

    .DESCRIPTION
    Returns the union of read-only Microsoft Graph permission scopes required
    by the selected assessment modules, plus the always-included Core module.
    The output is suitable for sharing with a customer's security team for
    consent approval before an engagement begins, and is the same scope set
    that Connect-ZTAssessment will request.

    .PARAMETER Modules
    The assessment modules to compute scopes for. Use Get-ZTAssessModuleCatalog
    to list valid module names. The Core module is always included and does
    not need to be specified.

    .PARAMETER AsScopeList
    Returns a plain, sorted, de-duplicated string array of scopes instead of
    one detail object per scope. Useful for piping directly to a connection.

    .EXAMPLE
    Get-ZTAssessRequiredPermission -Modules Identity, ConditionalAccess

    Returns one object per required scope showing which selected modules
    require it, including the always-included Core scopes.

    .EXAMPLE
    Get-ZTAssessRequiredPermission -Modules Devices -AsScopeList

    Returns the sorted scope strings required for a device assessment.

    .OUTPUTS
    PSCustomObject
    One object per scope with properties Scope and RequiredBy, or a string
    array when -AsScopeList is specified.

    .NOTES
    All scopes in the catalogue are read-only. This function performs no
    network calls and can be run before any connection exists.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject], [string[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Modules,

        [Parameter()]
        [switch]$AsScopeList
    )

    # Validates module names and loads the catalogue entries.
    $catalogueEntries = Get-ZTAssessModuleCatalog -Name $Modules -ErrorAction Stop

    # Always include the Core module scopes.
    $coreEntries = Get-ZTAssessModuleCatalog | Where-Object { $_.AlwaysIncluded }

    $scopeMap = [System.Collections.Generic.SortedDictionary[string, System.Collections.Generic.List[string]]]::new()

    foreach ($entry in (@($coreEntries) + @($catalogueEntries))) {
        foreach ($scope in $entry.Scopes) {
            if (-not $scopeMap.ContainsKey($scope)) {
                $scopeMap[$scope] = [System.Collections.Generic.List[string]]::new()
            }
            if ($scopeMap[$scope] -notcontains $entry.Name) {
                $scopeMap[$scope].Add($entry.Name)
            }
        }
    }

    if ($AsScopeList) {
        return [string[]]@($scopeMap.Keys)
    }

    foreach ($scopeName in $scopeMap.Keys) {
        [pscustomobject]@{
            PSTypeName = 'ZTAssess.RequiredPermission'
            Scope      = $scopeName
            RequiredBy = @($scopeMap[$scopeName])
        }
    }
}
