@{
    CheckId = 'AS-007'
    Domain = 'ApplicationSecurity'
    Title = 'Ownerless app registrations'
    Description = 'Flags app registrations holding credentials or permissions that have no owner.'
    Rationale = 'An ownerless app has no one to answer for its secrets, its permissions, or its continued existence.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'LeastPrivilege'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Application.Read.All'
    )
    DataSources = @(
        'applications'
    )
    Remediation = 'Assign at least one accountable owner to every app registration and fold ownerless apps into the application review cycle.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/enterprise-apps/overview-assign-app-owners'
    )
}
