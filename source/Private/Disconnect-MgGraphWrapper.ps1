#Requires -Version 7.0

# Wraps Disconnect-MgGraph for Pester mocking and dependency checking.
function Disconnect-MgGraphWrapper {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    if (-not (Get-Command -Name 'Disconnect-MgGraph' -ErrorAction SilentlyContinue)) {
        throw 'The Microsoft.Graph.Authentication module is required. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }

    $null = Disconnect-MgGraph -ErrorAction Stop
}
