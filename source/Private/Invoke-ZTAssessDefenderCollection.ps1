#Requires -Version 7.0

# Collects the latest Microsoft Secure Score entry, secure score control
# profile metadata, and unified security alerts for the Defender domain.
# Device onboarding coverage is assessed as a proxy via the relevant secure
# score control's contribution in the latest secureScores entry, since
# Microsoft Graph exposes no direct "onboarded machines" list for Defender
# for Endpoint.
function Invoke-ZTAssessDefenderCollection {
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
            Name  = 'secureScoreLatest'
            Fetch = {
                $latest = Invoke-ZTAssessGraphRequest -Uri '/v1.0/security/secureScores?$top=1'
                @($latest) | Select-Object -First 1
            }
        }
        @{
            Name  = 'secureScoreControlProfiles'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/security/secureScoreControlProfiles?$top=500&$select=id,controlName,title,category,service,rank,tier,maxScore,controlStateUpdates' -All }
        }
        @{
            Name  = 'unifiedAlerts'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/security/alerts_v2?$top=500&$select=id,title,severity,status,classification,createdDateTime,serviceSource,category' -All }
        }
    )

    return Invoke-ZTAssessCollectionSet -RunPath $RunPath -Specs $specs -Manifest $Manifest
}
