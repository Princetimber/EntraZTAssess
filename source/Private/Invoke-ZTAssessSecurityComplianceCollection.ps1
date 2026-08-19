#Requires -Version 7.0

# Collects Microsoft Purview retention and records-management configuration
# for the SecurityCompliance domain via the read-only Exchange Online / IPPS
# surface. Only called when Connect-ZTAssessment established that
# connection; the caller in Invoke-ZTAssessment is responsible for checking
# $connection.ExchangeOnlineConnected first.
function Invoke-ZTAssessSecurityComplianceCollection {
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
            Name  = 'retentionCompliancePolicies'
            Fetch = { Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-RetentionCompliancePolicy' }
        }
        @{
            Name  = 'retentionComplianceRules'
            Fetch = { Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-RetentionComplianceRule' }
        }
        @{
            Name  = 'complianceTags'
            Fetch = { Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-ComplianceTag' }
        }
    )

    return Invoke-ZTAssessCollectionSet -RunPath $RunPath -Specs $specs -Manifest $Manifest
}
