@{
    CheckId = 'CG-002'
    Domain = 'CorporateDeviceGovernance'
    Title = 'Device ownership tagging hygiene'
    Description = 'Flags managed devices with unknown ownership, which fall outside both the corporate and BYOD policy models.'
    Rationale = 'Every unknown-ownership device is governed by neither model: corporate policies may miss it and BYOD protections may not apply.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'LeastPrivilege'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementManagedDevices.Read.All'
    )
    DataSources = @(
        'managedDevices'
    )
    Remediation = 'Set device ownership on every managed device (corporate identifiers, enrolment profile defaults) and correct the unknown records.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/enrollment/corporate-identifiers-add'
    )
}
