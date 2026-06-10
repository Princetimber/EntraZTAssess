@{
    CheckId = 'HY-006'
    Domain = 'HybridIdentity'
    Title = 'Entra Connect version currency'
    Description = 'Checks the Entra Connect server version against the supported releases (manual verification; not exposed via Graph).'
    Rationale = 'Out-of-date Connect builds miss security fixes and eventually fall out of support, putting synchronisation itself at risk.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 1
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'None'
    PermissionDependency = @()
    DataSources = @()
    Remediation = 'Record the installed Entra Connect version from the server and upgrade to a currently supported build.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-install-automatic-upgrade'
    )
}
