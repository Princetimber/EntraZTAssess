#Requires -Version 7.0

# Collects Microsoft Purview Data Loss Prevention (DLP) and sensitivity
# label configuration for the DataProtection domain via the read-only
# Exchange Online / IPPS surface. Only called when Connect-ZTAssessment
# established that connection; the caller in Invoke-ZTAssessment is
# responsible for checking $connection.ExchangeOnlineConnected first.
function Invoke-ZTAssessDataProtectionCollection {
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
            Name  = 'dlpCompliancePolicies'
            Fetch = { Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-DlpCompliancePolicy' }
        }
        @{
            Name  = 'dlpComplianceRules'
            Fetch = { Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-DlpComplianceRule' }
        }
        @{
            Name  = 'sensitivityLabels'
            Fetch = { Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-Label' }
        }
        @{
            Name  = 'labelPolicies'
            Fetch = { Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-LabelPolicy' }
        }
    )

    return Invoke-ZTAssessCollectionSet -RunPath $RunPath -Specs $specs -Manifest $Manifest
}
