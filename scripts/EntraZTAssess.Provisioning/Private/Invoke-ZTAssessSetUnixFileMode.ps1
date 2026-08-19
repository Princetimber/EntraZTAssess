function Invoke-ZTAssessSetUnixFileMode {
    param(
        [string]$Path,
        $Mode
    )
    [System.IO.File]::SetUnixFileMode($Path, $Mode)
}
