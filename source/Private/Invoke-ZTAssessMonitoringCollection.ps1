#Requires -Version 7.0

# Collects the monitoring and detection data sets: risky users, an
# aggregate of risk detections (counts only - individual detections are
# not persisted), an audit log availability probe, and Defender for
# Identity sensor health (beta). Identity Protection endpoints require
# Entra ID P2 and degrade to NotAssessed without it.
function Invoke-ZTAssessMonitoringCollection {
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
            Name  = 'riskyUsers'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/identityProtection/riskyUsers?$select=id,userPrincipalName,riskLevel,riskState,riskLastUpdatedDateTime&$top=500' -All }
        }
        @{
            Name  = 'riskDetectionsSummary'
            Fetch = {
                $detections = Invoke-ZTAssessGraphRequest -Uri '/v1.0/identityProtection/riskDetections?$select=riskEventType,riskLevel,riskState&$top=999' -All

                $byType = $detections | Group-Object -Property riskEventType |
                    ForEach-Object { [pscustomobject]@{ riskEventType = $_.Name; count = $_.Count } }
                $byLevel = $detections | Group-Object -Property riskLevel |
                    ForEach-Object { [pscustomobject]@{ riskLevel = $_.Name; count = $_.Count } }

                [pscustomobject]@{
                    totalDetections = @($detections).Count
                    countsByType    = @($byType)
                    countsByLevel   = @($byLevel)
                }
            }
        }
        @{
            Name  = 'directoryAuditProbe'
            Fetch = {
                $sample = Invoke-ZTAssessGraphRequest -Uri '/v1.0/auditLogs/directoryAudits?$top=1'
                [pscustomobject]@{
                    available        = (@($sample).Count -gt 0)
                    sampledActivity  = if (@($sample).Count -gt 0) { $sample[0].activityDisplayName } else { $null }
                }
            }
        }
        @{
            Name  = 'mdiSensors'   # Defender for Identity sensor health (beta)
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/beta/security/identities/sensors?$select=id,displayName,healthStatus,sensorType' -All }
        }
    )

    return Invoke-ZTAssessCollectionSet -RunPath $RunPath -Specs $specs -Manifest $Manifest
}
