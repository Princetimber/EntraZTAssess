#Requires -Version 7.0

# Wraps Get-MgContext for Pester mocking and dependency checking.
function Get-MgContextWrapper {
    [CmdletBinding()]
    [OutputType([object])]
    param()

    if (-not (Get-Command -Name 'Get-MgContext' -ErrorAction SilentlyContinue)) {
        throw 'The Microsoft.Graph.Authentication module is required. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }

    return Get-MgContext
}
