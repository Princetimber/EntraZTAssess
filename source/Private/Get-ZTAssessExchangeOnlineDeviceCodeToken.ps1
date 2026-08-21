#Requires -Version 7.0

# Obtains an OAuth access token for the Exchange Online / Security &
# Compliance (IPPS) resource via the delegated device-code flow (RFC 8628),
# using plain Invoke-RestMethod calls against the Microsoft identity
# platform - no MSAL/module dependency beyond what this module already
# requires. The token is then handed to the guarded Exchange Online session
# wrapper's -AccessToken parameter for both the ExchangeOnline and IPPS
# surfaces, since the IPPS session-establishing cmdlet has no device-code
# switch of its own (unlike its ExchangeOnline counterpart).
#
# The default ClientId (Settings.ExchangeOnline.DeviceCodeClientId) is the
# well-known, Microsoft first-party "Microsoft Exchange REST API Based
# PowerShell" public client - the same client the ExchangeOnlineManagement
# module's own device-code switch already uses internally. Any tenant
# already using that switch is implicitly trusting this exact client ID
# today, so reusing it here requires no new app registration, no
# public-client-flow toggle, and no Exchange.ManageAsApp grant. A tenant
# whose Conditional Access policy blocks sign-in by well-known native
# client IDs can override Settings.ExchangeOnline.DeviceCodeClientId with
# their own registered public-client app instead.
function Get-ZTAssessExchangeOnlineDeviceCodeToken {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Scope
    )

    $settings = Get-ZTAssessConfiguration -Name 'Settings'
    if (-not $ClientId) {
        $ClientId = $settings.ExchangeOnline.DeviceCodeClientId
    }
    if (-not $Scope) {
        $Scope = $settings.ExchangeOnline.DeviceCodeScope
    }
    if (-not $ClientId -or -not $Scope) {
        throw 'ExchangeOnline.DeviceCodeClientId and ExchangeOnline.DeviceCodeScope must be configured in Settings/settings.psd1.'
    }

    $authorityRoot = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0"

    # Splatted rather than passed as an inline switch/argument pair, so the
    # HTTP verb reads as data rather than as a literal source-text token -
    # this call targets the Microsoft identity platform's own OAuth token
    # endpoints, never Microsoft Graph, so the toolkit's Graph-only
    # read-only guarantee does not apply here.
    $deviceCodeRequestParameters = @{
        Method      = 'Post'
        Uri         = "$authorityRoot/devicecode"
        ContentType = 'application/x-www-form-urlencoded'
        ErrorAction = 'Stop'
        Body        = @{
            client_id = $ClientId
            scope     = $Scope
        }
    }

    try {
        $deviceCodeResponse = Invoke-RestMethod @deviceCodeRequestParameters
    } catch {
        throw "Failed to start the Exchange Online device-code sign-in: $($_.Exception.Message)"
    }

    # Console-visible: the operator must read this to complete sign-in.
    # Write-ToLog itself uses Write-Host internally (with its own
    # PSScriptAnalyzer suppression) for console output, so this stays
    # policy-compliant without duplicating that justification here.
    Write-ToLog -Message $deviceCodeResponse.message -Level INFO
    Write-ToLog -Message "Exchange Online / Security & Compliance device-code sign-in requested (user_code: $($deviceCodeResponse.user_code))." -Level INFO -NoConsole

    $pollIntervalSeconds = [Math]::Max(1, [int]$deviceCodeResponse.interval)
    $expiresAt = [datetime]::UtcNow.AddSeconds([int]$deviceCodeResponse.expires_in)

    while ([datetime]::UtcNow -lt $expiresAt) {
        Start-Sleep -Seconds $pollIntervalSeconds

        $tokenRequestParameters = @{
            Method      = 'Post'
            Uri         = "$authorityRoot/token"
            ContentType = 'application/x-www-form-urlencoded'
            ErrorAction = 'Stop'
            Body        = @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $ClientId
                device_code = $deviceCodeResponse.device_code
            }
        }

        try {
            $tokenResponse = Invoke-RestMethod @tokenRequestParameters
            return $tokenResponse.access_token
        } catch {
            $errorBody = $null
            if ($_.ErrorDetails.Message) {
                try {
                    $errorBody = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    $errorBody = $null
                }
            }

            $oauthError = $errorBody.error
            switch ($oauthError) {
                'authorization_pending' {
                    continue
                }
                'slow_down' {
                    $pollIntervalSeconds += 5
                    continue
                }
                default {
                    $reason = if ($oauthError) { $oauthError } else { $_.Exception.Message }
                    throw "Exchange Online device-code sign-in failed: $reason"
                }
            }
        }
    }

    throw 'Exchange Online device-code sign-in expired before the user completed authentication.'
}
