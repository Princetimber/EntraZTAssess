#Requires -Version 7.0

# Collects Defender for Office 365 / Exchange Online Protection policy
# configuration for the ThreatProtection domain via the read-only Exchange
# Online / IPPS surface. Only called when Connect-ZTAssessment established
# that connection; the caller in Invoke-ZTAssessment is responsible for
# checking $connection.ExchangeOnlineConnected first.
function Invoke-ZTAssessThreatProtectionCollection {
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
            Name  = 'safeLinksPolicies'
            Fetch = { Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-SafeLinksPolicy' }
        }
        @{
            Name  = 'safeAttachmentPolicies'
            Fetch = { Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-SafeAttachmentPolicy' }
        }
        @{
            Name  = 'antiPhishPolicies'
            Fetch = { Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-AntiPhishPolicy' }
        }
        @{
            Name  = 'malwareFilterPolicies'
            Fetch = { Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-MalwareFilterPolicy' }
        }
    )

    return Invoke-ZTAssessCollectionSet -RunPath $RunPath -Specs $specs -Manifest $Manifest
}
