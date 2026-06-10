@{
    CheckId = 'MD-001'
    Domain = 'MonitoringDetection'
    Title = 'Risk-based policies enforced'
    Description = 'Verifies Identity Protection risk signals are enforced through Conditional Access risk policies.'
    Rationale = 'Risk detections that trigger no enforcement are a dashboard, not a control.'
    DefaultSeverity = 'High'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'VerifyExplicitly'
        'AssumeBreach'
    )
    LicenceDependency = 'Entra ID P2'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'conditionalAccessPolicies'
        'subscribedSkus'
    )
    Remediation = 'Enforce sign-in risk and user risk through Conditional Access policies (preferred over legacy Identity Protection policies).'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies'
    )
}
