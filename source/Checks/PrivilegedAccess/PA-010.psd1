@{
    CheckId = 'PA-010'
    Domain = 'PrivilegedAccess'
    Title = 'Privileged access bound to secured workstations'
    Description = 'Checks for a Conditional Access policy restricting privileged role usage to compliant or designated privileged access workstations.'
    Rationale = 'Tier-0 credentials used from unmanaged endpoints inherit every piece of malware on those endpoints; device binding closes that path.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'LeastPrivilege'
        'VerifyExplicitly'
        'AssumeBreach'
    )
    LicenceDependency = 'Entra ID P1 and Intune'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'conditionalAccessPolicies'
    )
    Remediation = 'Introduce a policy requiring compliant (ideally PAW-filtered) devices for directory role activation and use.'
    RemediationEffort = 'High'
    References = @(
        'https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-deployment'
    )
}
