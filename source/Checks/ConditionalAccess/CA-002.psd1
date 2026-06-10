@{
    CheckId = 'CA-002'
    Domain = 'ConditionalAccess'
    Title = 'Phishing-resistant MFA for administrators'
    Description = 'Verifies an enabled policy requires MFA, preferably a phishing-resistant authentication strength, for privileged directory roles.'
    Rationale = 'Administrator credentials are the highest-value target; they warrant stronger protection than the general user population.'
    DefaultSeverity = 'Critical'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'VerifyExplicitly'
        'LeastPrivilege'
    )
    LicenceDependency = 'Entra ID P1'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'conditionalAccessPolicies'
    )
    Remediation = 'Deploy a policy targeting directory roles requiring the phishing-resistant MFA authentication strength.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa'
    )
}
