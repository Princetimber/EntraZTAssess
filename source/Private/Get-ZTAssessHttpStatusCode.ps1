#Requires -Version 7.0

# Extracts an HTTP status code from an ErrorRecord raised by a Graph
# request. Returns 0 when no status code can be determined, which callers
# treat as non-retryable.
function Get-ZTAssessHttpStatusCode {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    # Preferred: a typed response object on the exception (HttpResponseException
    # and the Graph SDK exception types expose Response/StatusCode).
    $exception = $ErrorRecord.Exception

    if ($exception.PSObject.Properties['Response'] -and $exception.Response) {
        $response = $exception.Response
        if ($response.PSObject.Properties['StatusCode'] -and $response.StatusCode) {
            return [int]$response.StatusCode
        }
    }

    if ($exception.PSObject.Properties['StatusCode'] -and $exception.StatusCode) {
        return [int]$exception.StatusCode
    }

    # Fallback: parse a status code out of the message text.
    if ($exception.Message -match '\b(?<code>4\d\d|5\d\d)\b') {
        return [int]$Matches['code']
    }

    return 0
}
