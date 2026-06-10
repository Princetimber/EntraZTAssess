@{
    CheckId = 'MD-002'
    Domain = 'MonitoringDetection'
    Title = 'Risky users remediated promptly'
    Description = 'Measures open (at risk) users whose risk state has remained unremediated beyond the threshold (default 7 days).'
    Rationale = 'An unremediated high-risk user is a probably-compromised account that everyone has decided to ignore.'
    DefaultSeverity = 'High'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Entra ID P2'
    PermissionDependency = @(
        'IdentityRiskyUser.Read.All'
    )
    DataSources = @(
        'riskyUsers'
    )
    Remediation = 'Triage risky users daily: remediate with secure password change or block, and automate via user-risk Conditional Access.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-remediate-unblock'
    )
}
