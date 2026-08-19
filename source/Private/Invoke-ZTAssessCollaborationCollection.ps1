#Requires -Version 7.0

# Collects Exchange external sharing and mail-flow configuration for the
# Collaboration domain via the read-only Exchange Online / IPPS surface.
# Only called when Connect-ZTAssessment established that connection; the
# caller in Invoke-ZTAssessment is responsible for checking
# $connection.ExchangeOnlineConnected first. SharePoint tenant sharing
# settings (Get-SPOTenant) are out of scope for v1: they require a third
# connection surface (Connect-SPOService) not established by this module.
function Invoke-ZTAssessCollaborationCollection {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RunPath,

        [Parameter()]
        [ZTAssessRunManifest]$Manifest
    )

    $specs = @(
        @{
            Name  = 'sharingPolicies'
            Fetch = { Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-SharingPolicy' }
        }
        @{
            Name  = 'transportRules'
            Fetch = { Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-TransportRule' }
        }
    )

    return Invoke-ZTAssessCollectionSet -RunPath $RunPath -Specs $specs -Manifest $Manifest
}
