#Requires -Version 7.0

# Collects the core tenant data sets required by every assessment module:
# organisation metadata, licence SKUs, domains, and the projected user
# inventory. The user query attempts to include signInActivity (requires
# Entra ID P1 and AuditLog.Read.All) and silently degrades without it.
function Invoke-ZTAssessCoreCollection {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RunPath,

        [Parameter()]
        [ZTAssessRunManifest]$Manifest
    )

    $userSelect = 'id,userPrincipalName,displayName,accountEnabled,userType,onPremisesSyncEnabled,createdDateTime,assignedLicenses'

    $specs = @(
        @{
            Name  = 'organization'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/organization' }
        }
        @{
            Name  = 'subscribedSkus'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/subscribedSkus' -All }
        }
        @{
            Name  = 'domains'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/domains' -All }
        }
        @{
            Name  = 'users'
            Fetch = {
                try {
                    Invoke-ZTAssessGraphRequest -Uri "/v1.0/users?`$select=$userSelect,signInActivity&`$top=999" -All
                }
                catch {
                    # signInActivity requires Entra ID P1; retry without it.
                    Write-ToLog -Message 'User collection with signInActivity failed; retrying without it (staleness checks become NotAssessed).' -Level WARN -NoConsole
                    Invoke-ZTAssessGraphRequest -Uri "/v1.0/users?`$select=$userSelect&`$top=999" -All
                }
            }.GetNewClosure()
        }
        @{
            Name  = 'groups'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/groups?$select=id,displayName,isAssignableToRole,securityEnabled&$top=999' -All }
        }
    )

    return Invoke-ZTAssessCollectionSet -RunPath $RunPath -Specs $specs -Manifest $Manifest
}
