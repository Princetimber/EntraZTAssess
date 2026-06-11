#Requires -Version 7.0

function Protect-ZTAssessReportUserIdentifier {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$Context
    )

    $redactionMarker = '[RedactedUserIdentifier]'
    $json = ConvertTo-Json -InputObject $Context -Depth 50

    $json = Protect-ZTAssessReportUserIdentifierString -InputString $json -RedactionMarker $redactionMarker
    $redactedContext = $json | ConvertFrom-Json -Depth 50

    if ($null -ne $Context.GeneratedUtc) {
        $redactedContext.GeneratedUtc = [datetime]$Context.GeneratedUtc
    }

    return $redactedContext
}

function Protect-ZTAssessReportUserIdentifierString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$InputString,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RedactionMarker
    )

    $emailPattern = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    $fieldPattern = '(?i)("(?:userPrincipalName|ownerUserPrincipalName|mail|email|userId|displayName|userDisplayName|ownerDisplayName)"\s*:\s*)"(?:[^"\\]|\\.)*"'

    $redacted = [regex]::Replace($InputString, $emailPattern, $RedactionMarker)
    $redacted = [regex]::Replace(
        $redacted,
        $fieldPattern,
        {
            param($match)
            '{0}"{1}"' -f $match.Groups[1].Value, $RedactionMarker
        }
    )

    return $redacted
}
