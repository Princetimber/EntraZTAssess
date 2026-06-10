#Requires -Version 7.0

# Collects the privileged access data sets: role definitions, active role
# assignments, PIM eligibility and assignment schedules (Entra ID P2), role
# management policies, and a projected service principal inventory for
# privileged workload identity detection. PIM collectors degrade to
# NotAssessed on tenants without P2.
function Invoke-ZTAssessPrivilegedAccessCollection {
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
            Name  = 'roleDefinitions'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName,isBuiltIn' -All }
        }
        @{
            Name  = 'roleAssignments'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/roleManagement/directory/roleAssignments' -All }
        }
        @{
            Name  = 'roleEligibilitySchedules'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/roleManagement/directory/roleEligibilitySchedules' -All }
        }
        @{
            Name  = 'roleAssignmentSchedules'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/roleManagement/directory/roleAssignmentSchedules' -All }
        }
        @{
            Name  = 'roleManagementPolicies'
            Fetch = {
                $filter = [uri]::EscapeDataString("scopeId eq '/' and scopeType eq 'DirectoryRole'")
                Invoke-ZTAssessGraphRequest -Uri ('/v1.0/policies/roleManagementPolicies?$filter=' + $filter + '&$expand=rules') -All
            }
        }
        @{
            Name  = 'roleManagementPolicyAssignments'
            Fetch = {
                $filter = [uri]::EscapeDataString("scopeId eq '/' and scopeType eq 'DirectoryRole'")
                Invoke-ZTAssessGraphRequest -Uri ('/v1.0/policies/roleManagementPolicyAssignments?$filter=' + $filter) -All
            }
        }
        @{
            Name  = 'servicePrincipals'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled&$top=999' -All }
        }
    )

    return Invoke-ZTAssessCollectionSet -RunPath $RunPath -Specs $specs -Manifest $Manifest
}
