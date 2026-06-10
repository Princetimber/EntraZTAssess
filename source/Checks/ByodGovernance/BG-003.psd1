@{
    CheckId = 'BG-003'
    Domain = 'ByodGovernance'
    Title = 'Personal enrolment deliberately governed'
    Description = 'Reviews enrolment restrictions and flags tenants where personal enrolment is default-allowed on every platform with no restriction configured.'
    Rationale = 'Default-allow personal enrolment on all platforms is rarely a decision - it is usually an omission, and it silently expands the unmanaged estate.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'LeastPrivilege'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementServiceConfig.Read.All'
    )
    DataSources = @(
        'enrollmentConfigurations'
    )
    Remediation = 'Configure enrolment restrictions per platform: block personal enrolment where BYOD is not intended, and document the platforms where it is.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/enrollment/enrollment-restrictions-set'
    )
}
