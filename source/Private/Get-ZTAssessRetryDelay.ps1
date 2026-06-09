#Requires -Version 7.0

# Extracts the Retry-After header value (in seconds) from an ErrorRecord
# raised by a throttled Graph request. Returns 0 when the header is absent
# so callers fall back to exponential backoff.
function Get-ZTAssessRetryDelay {
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $exception = $ErrorRecord.Exception

    if ($exception.PSObject.Properties['Response'] -and $exception.Response) {
        $response = $exception.Response

        if ($response.PSObject.Properties['Headers'] -and $response.Headers) {
            $headers = $response.Headers

            # System.Net.Http.Headers.HttpResponseHeaders exposes RetryAfter.Delta
            if ($headers.PSObject.Properties['RetryAfter'] -and $headers.RetryAfter -and $headers.RetryAfter.Delta) {
                return [double]$headers.RetryAfter.Delta.TotalSeconds
            }

            # Hashtable-style headers (as surfaced by some SDK paths and mocks)
            if ($headers -is [System.Collections.IDictionary] -and $headers['Retry-After']) {
                $parsed = 0.0
                if ([double]::TryParse([string]$headers['Retry-After'], [ref]$parsed)) {
                    return $parsed
                }
            }
        }
    }

    return 0
}
