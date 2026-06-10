#Requires -Version 7.0

# Collects the device trust and endpoint management data sets: Intune
# managed devices, Entra device objects, compliance policies, configuration
# profiles, settings catalog policies, security baselines (intents), app
# protection policies, enrolment configurations, Autopilot, Apple and
# Android enrolment connectors, the Defender for Endpoint connector, and
# tenant device management settings.
#
# Several Intune data sets have no v1.0 equivalent and are collected from
# the beta endpoint; these are marked with '(beta)' and degrade to
# NotAssessed if Microsoft changes them.
function Invoke-ZTAssessDeviceCollection {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RunPath,

        [Parameter()]
        [ZTAssessRunManifest]$Manifest
    )

    $deviceSelect = 'id,deviceName,operatingSystem,osVersion,managedDeviceOwnerType,deviceEnrollmentType,complianceState,isEncrypted,isSupervised,lastSyncDateTime,managementAgent,model,manufacturer,userPrincipalName,azureADDeviceId,serialNumber'

    $specs = @(
        @{
            Name  = 'managedDevices'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri "/v1.0/deviceManagement/managedDevices?`$select=$deviceSelect&`$top=999" -All }.GetNewClosure()
        }
        @{
            Name  = 'entraDevices'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/devices?$select=id,deviceId,displayName,operatingSystem,trustType,profileType,isManaged,isCompliant,accountEnabled,approximateLastSignInDateTime,systemLabels&$top=999' -All }
        }
        @{
            Name  = 'compliancePolicies'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/deviceManagement/deviceCompliancePolicies?$expand=assignments' -All }
        }
        @{
            Name  = 'deviceConfigurations'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/deviceManagement/deviceConfigurations?$expand=assignments' -All }
        }
        @{
            Name  = 'configurationPolicies'   # settings catalog (beta)
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/beta/deviceManagement/configurationPolicies?$expand=assignments&$select=id,name,platforms,technologies,templateReference' -All }
        }
        @{
            Name  = 'intents'                 # security baselines / endpoint security (beta)
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/beta/deviceManagement/intents?$select=id,displayName,templateId,isAssigned' -All }
        }
        @{
            Name  = 'appProtectionPolicies'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/deviceAppManagement/managedAppPolicies' -All }
        }
        @{
            Name  = 'enrollmentConfigurations'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/deviceManagement/deviceEnrollmentConfigurations' -All }
        }
        @{
            Name  = 'autopilotDevices'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$select=id,serialNumber,model,manufacturer&$top=999' -All }
        }
        @{
            Name  = 'autopilotProfiles'       # (beta)
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/beta/deviceManagement/windowsAutopilotDeploymentProfiles?$select=id,displayName' -All }
        }
        @{
            Name  = 'applePushCertificate'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/deviceManagement/applePushNotificationCertificate' }
        }
        @{
            Name  = 'depOnboardingSettings'   # ABM / ADE tokens (beta)
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/beta/deviceManagement/depOnboardingSettings?$select=id,tokenName,tokenExpirationDateTime,appleIdentifier' -All }
        }
        @{
            Name  = 'androidEnterpriseSettings' # managed Google Play binding (beta)
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings' }
        }
        @{
            Name  = 'mtdConnectors'
            Fetch = { Invoke-ZTAssessGraphRequest -Uri '/v1.0/deviceManagement/mobileThreatDefenseConnectors' -All }
        }
        @{
            Name  = 'deviceManagementSettings'
            Fetch = {
                $result = Invoke-ZTAssessGraphRequest -Uri '/v1.0/deviceManagement?$select=settings'
                $result[0].settings
            }
        }
    )

    return Invoke-ZTAssessCollectionSet -RunPath $RunPath -Specs $specs -Manifest $Manifest
}
