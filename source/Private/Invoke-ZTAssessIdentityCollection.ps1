#Requires -Version 7.0

# Collects the identity security data sets: MFA registration details,
# authentication methods policy, security defaults state, and an aggregate
# of legacy authentication sign-ins over the lookback window. Sign-in data
# is aggregated client-side to counts per client app - individual sign-in
# records are never persisted.
function Invoke-ZTAssessIdentityCollection {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RunPath,

        [Parameter()]
        [ValidateRange(1, 90)]
        [int]$SignInLookbackDays = 30,

        [Parameter()]
        [ZTAssessRunManifest]$Manifest
    )

    $lookbackStart = [datetime]::UtcNow.AddDays(-$SignInLookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')

    $specs = @(
        @{
            Name  = 'userRegistrationDetails'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999' -All }
        }
        @{
            Name  = 'authenticationMethodsPolicy'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/policies/authenticationMethodsPolicy' }
        }
        @{
            Name  = 'securityDefaultsPolicy'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' }
        }
        @{
            Name  = 'legacyAuthSignIns'
            Fetch = {
                $filter = "createdDateTime ge $lookbackStart and clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients'"
                $uri = '/v1.0/auditLogs/signIns?$filter=' + [uri]::EscapeDataString($filter) + '&$select=clientAppUsed&$top=999'
                $signIns = Invoke-ZTAssessGraphRequest -Uri $uri -All

                # Aggregate to counts per client app; never persist raw sign-ins.
                $aggregate = $signIns | Group-Object -Property clientAppUsed | ForEach-Object {
                    [pscustomobject]@{
                        clientAppUsed = $_.Name
                        count         = $_.Count
                    }
                }

                [pscustomobject]@{
                    lookbackDays      = $SignInLookbackDays
                    lookbackStartUtc  = $lookbackStart
                    totalLegacyCount  = ($signIns | Measure-Object).Count
                    countsByClientApp = @($aggregate)
                }
            }.GetNewClosure()
        }
    )

    return Invoke-ZTAssessCollectionSet -RunPath $RunPath -Specs $specs -Manifest $Manifest
}
