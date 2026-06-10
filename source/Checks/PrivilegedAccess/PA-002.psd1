@{
    CheckId = 'PA-002'
    Domain = 'PrivilegedAccess'
    Title = 'Privileged access via PIM eligibility'
    Description = 'Measures the proportion of privileged assignments that are PIM-eligible rather than permanently active; flags permanent Global Administrators beyond break-glass.'
    Rationale = 'Standing privilege is standing risk: permanently active roles are exploitable around the clock, while just-in-time activation shrinks the window to minutes.'
    DefaultSeverity = 'High'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'LeastPrivilege'
        'AssumeBreach'
    )
    LicenceDependency = 'Entra ID P2'
    PermissionDependency = @(
        'RoleEligibilitySchedule.Read.Directory'
        'RoleAssignmentSchedule.Read.Directory'
    )
    DataSources = @(
        'roleEligibilitySchedules'
        'roleAssignmentSchedules'
        'roleAssignments'
    )
    Remediation = 'Convert permanent privileged assignments to PIM-eligible with activation requirements, retaining only break-glass as permanent.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure'
    )
}
