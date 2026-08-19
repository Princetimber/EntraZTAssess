#Requires -Version 7.0

# Dispatches a single, allow-listed read-only Exchange Online / Security &
# Compliance (IPPS) cmdlet. This is the sole entry point collectors may use
# for that surface, mirroring Invoke-MgGraphRequestWrapper's GET-only
# restriction for Microsoft Graph. -CmdletName is validated against
# Get-ZTAssessExoAllowedCmdletName so only Get-* cmdlets can ever be invoked;
# the read-only QA gate additionally verifies no caller bypasses this wrapper.
function Invoke-ZTAssessExoRequestWrapper {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({
                if ($_ -notin (Get-ZTAssessExoAllowedCmdletName)) {
                    throw "'$_' is not an allowed read-only Exchange Online/IPPS cmdlet."
                }
                $true
            })]
        [string]$CmdletName,

        [Parameter()]
        [hashtable]$Parameters = @{}
    )

    if (-not (Get-Command -Name $CmdletName -ErrorAction SilentlyContinue)) {
        throw "The required cmdlet '$CmdletName' is not available. Ensure ExchangeOnlineManagement is installed and Connect-ExchangeOnlineWrapper succeeded."
    }

    return & $CmdletName @Parameters -ErrorAction Stop
}
