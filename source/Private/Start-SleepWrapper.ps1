#Requires -Version 7.0

# Wraps Start-Sleep for Pester mocking so retry/backoff tests run instantly.
function Start-SleepWrapper {
    [CmdletBinding()]
    [OutputType([void])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Thin wrapper around Start-Sleep for Pester mocking; no system state is changed.')]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(0, 3600)]
        [double]$Seconds
    )

    Start-Sleep -Seconds $Seconds
}
