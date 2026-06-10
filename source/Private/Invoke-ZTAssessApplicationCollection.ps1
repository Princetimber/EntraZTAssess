#Requires -Version 7.0

# Collects the application security data sets: app registrations
# (credential metadata only - never key material, which the redaction
# denylist additionally strips), delegated OAuth grants, the Microsoft
# Graph service principal (for app role name resolution), application role
# assignments against Microsoft Graph, and optional service principal
# sign-in activity (beta).
function Invoke-ZTAssessApplicationCollection {
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
            Name  = 'applications'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/applications?$select=id,appId,displayName,signInAudience,web,spa,publicClient,keyCredentials,passwordCredentials,verifiedPublisher&$expand=owners($select=id)&$top=999' -All }
        }
        @{
            Name  = 'oauth2PermissionGrants'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/oauth2PermissionGrants?$top=999' -All }
        }
        @{
            Name  = 'graphServicePrincipal'
            Fetch = {
                $filter = [uri]::EscapeDataString("appId eq '00000003-0000-0000-c000-000000000000'")
                $result = Invoke-ZTAssessGraphRequest -Uri ('/v1.0/servicePrincipals?$filter=' + $filter + '&$select=id,appId,displayName,appRoles')
                $result[0]
            }
        }
        @{
            Name  = 'graphAppRoleAssignments'
            Fetch = {
                # Application permissions granted against Microsoft Graph:
                # resolve the Graph service principal, then list every
                # principal holding one of its app roles.
                $filter = [uri]::EscapeDataString("appId eq '00000003-0000-0000-c000-000000000000'")
                $graphSp = Invoke-ZTAssessGraphRequest -Uri ('/v1.0/servicePrincipals?$filter=' + $filter + '&$select=id')
                Invoke-ZTAssessGraphRequest -Uri "/v1.0/servicePrincipals/$($graphSp[0].id)/appRoleAssignedTo?`$top=999" -All
            }
        }
        @{
            Name  = 'spSignInActivities'   # workload identity sign-in activity (beta)
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/beta/reports/servicePrincipalSignInActivities?$top=999' -All }
        }
    )

    return Invoke-ZTAssessCollectionSet -RunPath $RunPath -Specs $specs -Manifest $Manifest
}
