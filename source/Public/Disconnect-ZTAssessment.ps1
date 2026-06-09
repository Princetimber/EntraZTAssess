#Requires -Version 7.0

function Disconnect-ZTAssessment {
    <#
    .SYNOPSIS
    Disconnects the current Microsoft Graph assessment session.

    .DESCRIPTION
    Ends the Microsoft Graph session established by Connect-ZTAssessment and
    clears the cached connection summary held by the module. Run this at the
    end of every engagement so no authenticated context remains on the
    consultant workstation.

    .EXAMPLE
    Disconnect-ZTAssessment

    Ends the current Microsoft Graph session and clears the cached
    connection summary.

    .OUTPUTS
    None. A confirmation entry is written to the module log.

    .NOTES
    Safe to call when no connection exists; a warning is written and the
    cached state is still cleared.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()

    try {
        Disconnect-MgGraphWrapper
        Write-ToLog -Message 'Disconnected from Microsoft Graph.' -Level INFO -NoConsole
    }
    catch {
        Write-Warning "No active Microsoft Graph session to disconnect, or disconnection failed: $($_.Exception.Message)"
        Write-ToLog -Message "Disconnect attempt: $($_.Exception.Message)" -Level WARN -NoConsole
    }
    finally {
        $script:ZTAssessConnection = $null
    }
}
