@{
    CheckId = 'ID-004'
    Domain = 'IdentitySecurity'
    Title = 'Baseline protection in force'
    Description = 'Confirms that either security defaults or enforced Conditional Access policies protect the tenant; flags tenants with neither, and conflicts where both are configured.'
    Rationale = 'A tenant with neither security defaults nor Conditional Access has no baseline identity protection at all.'
    DefaultSeverity = 'Critical'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'securityDefaultsPolicy'
        'conditionalAccessPolicies'
    )
    Remediation = 'Enable security defaults for unlicensed tenants, or implement a Conditional Access baseline policy set where Entra ID P1 is available.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/fundamentals/security-defaults'
    )
}
