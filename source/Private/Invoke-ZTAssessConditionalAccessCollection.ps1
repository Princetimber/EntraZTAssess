#Requires -Version 7.0

# Collects the Conditional Access data sets: full policy definitions,
# named locations, and authentication strength policies.
function Invoke-ZTAssessConditionalAccessCollection {
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
            Name  = 'conditionalAccessPolicies'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/identity/conditionalAccess/policies' -All }
        }
        @{
            Name  = 'namedLocations'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/identity/conditionalAccess/namedLocations' -All }
        }
        @{
            Name  = 'authenticationStrengthPolicies'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/policies/authenticationStrengthPolicies' -All }
        }
    )

    return Invoke-ZTAssessCollectionSet -RunPath $RunPath -Specs $specs -Manifest $Manifest
}
