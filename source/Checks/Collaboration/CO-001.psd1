@{
    CheckId = 'CO-001'
    Domain = 'Collaboration'
    Title = 'Anonymous users cannot see detailed calendar free/busy information'
    Description = 'Evaluates whether any enabled Exchange sharing policy grants anonymous (unauthenticated) users calendar free/busy detail or full details, rather than only simple free/busy blocks.'
    Rationale = 'Anonymous access to calendar subject, location, or attendee detail leaks internal meeting context to anyone with a calendar URL, without any authentication.'
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
    Remediation = 'Edit every enabled sharing policy so the Anonymous domain entry, if present, is scoped to CalendarSharingFreeBusySimple only, never Detail or FullDetails.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/exchange/sharing/sharing-policies/sharing-policies'
    )
}
