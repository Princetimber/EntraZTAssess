#Requires -Version 7.0

# Single source of truth for the read-only Exchange Online / Security &
# Compliance (IPPS) cmdlets this module is permitted to call. Consumed by
# Invoke-ZTAssessExoRequestWrapper (parameter validation) and by
# Connect-ExchangeOnlineWrapper (-CommandName session scoping), so a session
# never even imports a write-capable proxy function. Every entry must be a
# Get-* cmdlet; enforced by tests/QA/ReadOnly.tests.ps1.
function Get-ZTAssessExoAllowedCmdletName {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return [string[]]@(
        'Get-DlpCompliancePolicy'
        'Get-DlpComplianceRule'
        'Get-Label'
        'Get-LabelPolicy'
        'Get-RetentionCompliancePolicy'
        'Get-RetentionComplianceRule'
        'Get-ComplianceTag'
        'Get-AntiPhishPolicy'
        'Get-SafeLinksPolicy'
        'Get-SafeAttachmentPolicy'
        'Get-HostedContentFilterPolicy'
        'Get-MalwareFilterPolicy'
        'Get-TransportRule'
        'Get-SharingPolicy'
        'Get-OrganizationConfig'
    )
}
