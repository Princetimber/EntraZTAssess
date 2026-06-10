#Requires -Version 7.0

# Collects the identity governance data sets: access review definitions,
# entitlement management access packages, lifecycle workflows, the tenant
# authorisation policy (guest and consent settings), the default
# cross-tenant access policy, and the admin consent request policy.
# Governance endpoints require Entra ID P2/Governance licensing and degrade
# to NotAssessed without it.
function Invoke-ZTAssessGovernanceCollection {
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
            Name  = 'accessReviewDefinitions'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/identityGovernance/accessReviews/definitions' -All }
        }
        @{
            Name  = 'accessPackages'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/identityGovernance/entitlementManagement/accessPackages?$select=id,displayName,isHidden' -All }
        }
        @{
            Name  = 'lifecycleWorkflows'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/identityGovernance/lifecycleWorkflows/workflows?$select=id,displayName,category,isEnabled' -All }
        }
        @{
            Name  = 'authorizationPolicy'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/policies/authorizationPolicy' }
        }
        @{
            Name  = 'crossTenantAccessPolicyDefault'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/policies/crossTenantAccessPolicy/default' }
        }
        @{
            Name  = 'adminConsentRequestPolicy'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/policies/adminConsentRequestPolicy' }
        }
    )

    return Invoke-ZTAssessCollectionSet -RunPath $RunPath -Specs $specs -Manifest $Manifest
}
