@{
    CheckId = 'DT-003'
    Domain = 'DeviceTrust'
    Title = 'Devices without compliance policy not marked compliant'
    Description = 'Checks the tenant compliance setting that controls whether devices with no compliance policy assigned are treated as compliant (secure by default).'
    Rationale = 'If unassigned devices default to compliant, every gap in compliance policy assignment silently satisfies compliant-device Conditional Access - the control inverts.'
    DefaultSeverity = 'High'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'VerifyExplicitly'
        'AssumeBreach'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementConfiguration.Read.All'
    )
    DataSources = @(
        'deviceManagementSettings'
        'conditionalAccessPolicies'
    )
    Remediation = 'Set "Mark devices with no compliance policy assigned" to Not compliant in Intune compliance policy settings.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/protect/device-compliance-get-started'
    )
}
