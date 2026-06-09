#Requires -Version 7.0

# Read-only Microsoft Graph request helper used by every collector.
# Provides @odata.nextLink paging, 429 throttling handling (honours
# Retry-After), and transient 5xx retries with exponential backoff.
# Only GET requests are possible: the underlying wrapper rejects any
# other method, enforcing the module's read-only guarantee.
function Invoke-ZTAssessGraphRequest {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^(https://|/)')]
        [string]$Uri,

        [Parameter()]
        [switch]$All,

        [Parameter()]
        [ValidateRange(0, 10)]
        [int]$MaxRetryCount = -1
    )

    $graphSettings = (Get-ZTAssessConfiguration -Name Settings).Graph

    if ($MaxRetryCount -lt 0) {
        $MaxRetryCount = [int]$graphSettings.MaxRetryCount
    }

    $baseDelaySeconds = [double]$graphSettings.RetryBaseDelaySeconds
    $results = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri
    $pageCount = 0

    while ($nextUri) {
        $attempt = 0
        $response = $null

        while ($true) {
            try {
                Write-ToLog -Message "Graph GET $nextUri (attempt $($attempt + 1))" -Level DEBUG -NoConsole
                $response = Invoke-MgGraphRequestWrapper -Uri $nextUri -Method GET -OutputType PSObject
                break
            }
            catch {
                $statusCode = Get-ZTAssessHttpStatusCode -ErrorRecord $_

                $isRetryable = ($statusCode -eq 429) -or ($statusCode -ge 500 -and $statusCode -le 599)

                if (-not $isRetryable -or $attempt -ge $MaxRetryCount) {
                    Write-ToLog -Message "Graph request failed for $nextUri (status: $statusCode): $($_.Exception.Message)" -Level ERROR -NoConsole
                    throw
                }

                $retryAfterSeconds = Get-ZTAssessRetryDelay -ErrorRecord $_
                if (-not $retryAfterSeconds) {
                    $retryAfterSeconds = [math]::Pow(2, $attempt) * $baseDelaySeconds
                }

                Write-ToLog -Message "Graph request throttled or transient failure (status: $statusCode). Retrying in $retryAfterSeconds second(s)." -Level WARN -NoConsole
                Start-SleepWrapper -Seconds $retryAfterSeconds
                $attempt++
            }
        }

        $pageCount++

        # Collection responses expose 'value'; single-entity responses do not.
        if ($null -ne $response.PSObject.Properties['value']) {
            foreach ($item in $response.value) {
                $results.Add($item)
            }
        }
        else {
            $results.Add($response)
        }

        $nextLink = $response.PSObject.Properties['@odata.nextLink']
        if ($All -and $nextLink -and $nextLink.Value) {
            $nextUri = [string]$nextLink.Value
        }
        else {
            $nextUri = $null
        }
    }

    Write-ToLog -Message "Graph GET complete: $Uri ($($results.Count) record(s), $pageCount page(s))" -Level DEBUG -NoConsole

    return , $results.ToArray()
}
