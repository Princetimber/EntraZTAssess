@{
    CheckId = 'CO-003'
    Domain = 'Collaboration'
    Title = 'Full calendar details are not shared with every external domain'
    Description = 'Evaluates whether any enabled Exchange sharing policy grants full calendar details (subject, location, attendees) to all external domains via a wildcard entry, rather than a named, deliberately-scoped partner domain.'
    Rationale = 'A wildcard full-details entry shares complete meeting content with every external organisation a user corresponds with, not just an intended sharing partner.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'LeastPrivilege'
    )
    LicenceDependency = ''
    PermissionDependency = @()
    DataSources = @(
        'sharingPolicies'
    )
    Remediation = 'Replace any wildcard (all-domain) full-details sharing entry with named partner domains, and confirm each is a deliberate business relationship.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/exchange/sharing/sharing-policies/sharing-policies'
    )
}
