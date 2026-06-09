#Requires -Version 7.0

# Wraps Invoke-MgGraphRequest for Pester mocking and dependency checking.
# The Method parameter is deliberately restricted to GET: this module is
# read-only by default and no collector may issue a write request. The
# read-only QA gate additionally verifies no caller bypasses this wrapper.
function Invoke-MgGraphRequestWrapper {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET')]
        [string]$Method = 'GET',

        [Parameter()]
        [ValidateSet('PSObject', 'HashTable', 'Json')]
        [string]$OutputType = 'PSObject'
    )

    if (-not (Get-Command -Name 'Invoke-MgGraphRequest' -ErrorAction SilentlyContinue)) {
        throw 'The Microsoft.Graph.Authentication module is required. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }

    return Invoke-MgGraphRequest -Uri $Uri -Method $Method -OutputType $OutputType -ErrorAction Stop
}
