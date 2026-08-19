#Requires -Version 7.0

function Get-ZTAssessExchangeOnlineRoleGuidance {
    <#
    .SYNOPSIS
    Lists the Exchange Online / Security & Compliance role groups required by
    the selected assessment modules.

    .DESCRIPTION
    Reads the read-only permission catalogue and returns the Exchange Online
    / Security & Compliance (IPPS) role groups that must be granted to the
    EntraZTAssess app registration's service principal for modules that read
    Purview/Exchange configuration (SecurityCompliance, Collaboration,
    DataProtection, ThreatProtection).

    This function performs no network calls and makes no writes: it only
    reads the local permission catalogue and prints guidance. Granting the
    listed role groups can be done either manually by the tenant's own
    Exchange administrator (for example via the Microsoft 365 admin center,
    or by running Add-RoleGroupMember themselves), or with
    Grant-ZTAssessExchangeOnlineRole in this module, which automates the
    same Exchange Online RBAC write. This function itself remains read-only
    either way.

    .PARAMETER Modules
    Assessment modules to scope the guidance to. Use Get-ZTAssessModuleCatalog
    to list valid names. Defaults to every module in the catalogue; modules
    that do not require Exchange Online / IPPS are silently omitted from the
    result.

    .EXAMPLE
    Get-ZTAssessExchangeOnlineRoleGuidance -Modules ThreatProtection

    Lists the Exchange Online / IPPS role groups required for the
    ThreatProtection module.

    .OUTPUTS
    PSCustomObject
    One object per module that requires Exchange Online / IPPS, with
    properties Module, ExchangeOnlineRoles, and Description.

    .NOTES
    Exact role-group names vary slightly by tenant license and national
    cloud; confirm availability in the Microsoft Purview / Exchange admin
    center before assigning them.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Modules
    )

    $permissionsPath = Join-Path -Path $PSScriptRoot -ChildPath '../../../source/Settings/permissions.psd1'
    if (-not (Test-Path -LiteralPath $permissionsPath)) {
        throw "Permission catalogue not found at $permissionsPath."
    }

    $catalogue = (Import-PowerShellDataFile -Path $permissionsPath).Modules

    $selectedKeys = if ($Modules) {
        $unknownModules = @($Modules | Where-Object { -not $catalogue.ContainsKey($_) })
        if ($unknownModules.Count -gt 0) {
            throw ('Unknown module(s): {0}. Valid modules: {1}.' -f ($unknownModules -join ', '), (($catalogue.Keys | Sort-Object) -join ', '))
        }
        $Modules
    } else {
        $catalogue.Keys | Sort-Object
    }

    foreach ($moduleKey in $selectedKeys) {
        $entry = $catalogue[$moduleKey]
        if (-not $entry.RequiresExchangeOnline) {
            continue
        }

        [pscustomobject]@{
            PSTypeName          = 'ZTAssess.ExchangeOnlineRoleGuidance'
            Module              = $moduleKey
            ExchangeOnlineRoles = @($entry.ExchangeOnlineRoles)
            Description         = $entry.Description
        }
    }
}
