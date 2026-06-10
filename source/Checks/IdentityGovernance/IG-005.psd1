@{
    CheckId = 'IG-005'
    Domain = 'IdentityGovernance'
    Title = 'Guest invitation and permission settings'
    Description = 'Reviews who may invite guests and the directory permission level guests receive.'
    Rationale = 'Everyone-can-invite plus full guest directory read turns the tenant boundary into a suggestion.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'LeastPrivilege'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'authorizationPolicy'
    )
    Remediation = 'Restrict guest invitations to admins and designated inviters, and set guest access to the restricted permission level.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/external-id/external-collaboration-settings-configure'
    )
}
