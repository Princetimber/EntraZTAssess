#Requires -Version 7.0

# Wraps Disconnect-ExchangeOnline for Pester mocking and dependency checking.
# A single disconnect call tears down both the Exchange Online and IPPS
# surfaces, since Connect-IPPSSession registers its session under the same
# remote PSSession that Disconnect-ExchangeOnline closes.
function Disconnect-ExchangeOnlineWrapper {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    if (-not (Get-Command -Name 'Disconnect-ExchangeOnline' -ErrorAction SilentlyContinue)) {
        throw 'The ExchangeOnlineManagement module is required. Install it with: Install-Module ExchangeOnlineManagement -Scope CurrentUser'
    }

    $null = Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
}
