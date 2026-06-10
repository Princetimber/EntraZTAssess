@{
    CheckId = 'WIN-002'
    Domain = 'EndpointManagement'
    Title = 'Personal Windows enrolment mitigated'
    Description = 'Flags tenants where personal Windows enrolment is permitted without a Windows app protection policy or compliant-device Conditional Access mitigation.'
    Rationale = 'Personal Windows devices with full enrolment but no data controls combine the broadest data access with the weakest governance.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'VerifyExplicitly'
        'AssumeBreach'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementServiceConfig.Read.All'
        'DeviceManagementApps.Read.All'
    )
    DataSources = @(
        'enrollmentConfigurations'
        'appProtectionPolicies'
        'conditionalAccessPolicies'
    )
    Remediation = 'Block personal Windows enrolment, or mitigate with Windows MAM and compliant-device Conditional Access.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/enrollment/enrollment-restrictions-set'
    )
}
