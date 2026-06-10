@{
    CheckId = 'PA-005'
    Domain = 'PrivilegedAccess'
    Title = 'Separate admin accounts for daily-driver users'
    Description = 'Heuristically flags privileged accounts that appear to double as daily productivity accounts (standard naming plus productivity licensing); requires consultant confirmation.'
    Rationale = 'Browsing and email expose admin sessions to phishing and drive-by attacks; separation of duties demands separate accounts.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'LeastPrivilege'
        'AssumeBreach'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'RoleManagement.Read.Directory'
        'Directory.Read.All'
    )
    DataSources = @(
        'roleAssignments'
        'users'
    )
    Remediation = 'Issue dedicated admin accounts (no mailbox, no productivity licence) and remove roles from daily-driver identities.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-access-model'
    )
}
