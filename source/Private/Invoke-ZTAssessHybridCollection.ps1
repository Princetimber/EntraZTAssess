#Requires -Version 7.0

# Collects the hybrid identity data sets: the on-premises directory
# synchronisation configuration and an aggregate of user provisioning
# errors. Error details are aggregated to counts by category - individual
# error payloads are not persisted.
function Invoke-ZTAssessHybridCollection {
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
            Name  = 'onPremisesSynchronization'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/directory/onPremisesSynchronization' -All }
        }
        @{
            Name  = 'provisioningErrorsSummary'
            Fetch = {
                $records = Invoke-ZTAssessGraphRequest -Uri '/v1.0/users?$select=id,onPremisesSyncEnabled,onPremisesProvisioningErrors&$top=999' -All

                $synced = @($records | Where-Object { $_.onPremisesSyncEnabled })
                $withErrors = @($synced | Where-Object { @($_.onPremisesProvisioningErrors).Count -gt 0 })
                $categories = $withErrors |
                    ForEach-Object { @($_.onPremisesProvisioningErrors) } |
                    Group-Object -Property category |
                    ForEach-Object { [pscustomobject]@{ category = $_.Name; count = $_.Count } }

                [pscustomobject]@{
                    syncedUserCount     = $synced.Count
                    usersWithErrors     = $withErrors.Count
                    errorsByCategory    = @($categories)
                }
            }
        }
    )

    return Invoke-ZTAssessCollectionSet -RunPath $RunPath -Specs $specs -Manifest $Manifest
}
