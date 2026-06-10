@{
    CheckId = 'IG-006'
    Domain = 'IdentityGovernance'
    Title = 'Cross-tenant access posture reviewed'
    Description = 'Reports the default cross-tenant access settings, including whether MFA and device claims from external tenants are trusted.'
    Rationale = 'Cross-tenant trust settings silently decide whether external MFA satisfies your Conditional Access; defaults deserve a deliberate decision.'
    DefaultSeverity = 'Low'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'crossTenantAccessPolicyDefault'
    )
    Remediation = 'Review default inbound/outbound cross-tenant settings and trust configuration, and document the intended posture per partner.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/external-id/cross-tenant-access-overview'
    )
}
