@{
    CheckId = 'DT-002'
    Domain = 'DeviceTrust'
    Title = 'Compliance policy per active platform'
    Description = 'Verifies a compliance policy exists and is assigned for every platform with enrolled devices.'
    Rationale = 'A platform without a compliance policy reports every device as having no signal, silently weakening compliant-device Conditional Access.'
    DefaultSeverity = 'High'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementConfiguration.Read.All'
        'DeviceManagementManagedDevices.Read.All'
    )
    DataSources = @(
        'compliancePolicies'
        'managedDevices'
    )
    Remediation = 'Create and assign a compliance policy for each enrolled platform before relying on device compliance in Conditional Access.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/protect/device-compliance-get-started'
    )
}
