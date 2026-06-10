@{
    CheckId = 'AS-002'
    Domain = 'ApplicationSecurity'
    Title = 'High-privilege application permissions'
    Description = 'Enumerates service principals holding Tier-0 or high-risk Microsoft Graph application permissions, excluding Microsoft first-party services.'
    Rationale = 'An app permission such as RoleManagement.ReadWrite.Directory is a standing path to Global Administrator that no MFA ever challenges.'
    DefaultSeverity = 'Critical'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'LeastPrivilege'
        'AssumeBreach'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Application.Read.All'
    )
    DataSources = @(
        'graphAppRoleAssignments'
        'graphServicePrincipal'
        'servicePrincipals'
    )
    Remediation = 'Inventory every Tier-0 application permission, remove those not strictly required, and protect the remainder with credential hygiene and monitoring.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/enterprise-apps/grant-admin-consent'
    )
}
