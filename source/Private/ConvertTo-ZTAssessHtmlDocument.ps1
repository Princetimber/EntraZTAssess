#Requires -Version 7.0

# Shared HTML document shell for all toolkit reports. Produces a fully
# self-contained page (inline CSS, no external assets) with classification
# banners, engagement header, and footer. All visible text in British
# English.
function ConvertTo-ZTAssessHtmlDocument {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$BodyHtml,

        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $encode = { param($value) [System.Net.WebUtility]::HtmlEncode([string]$value) }

    $classification = & $encode $Context.Engagement.Classification
    $customer = & $encode $Context.Engagement.CustomerName
    $reference = & $encode $Context.Engagement.Reference
    $generated = $Context.GeneratedUtc.ToString('dd MMMM yyyy HH:mm') + ' UTC'
    $tenant = & $encode $Context.Manifest.TenantId

    return @"
<!DOCTYPE html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(& $encode $Title)</title>
<style>
:root { --critical:#a4262c; --high:#d83b01; --medium:#ca8a04; --low:#0f6cbd; --pass:#107c10; --na:#605e5c; --ink:#1b1a19; --muted:#605e5c; --line:#e1dfdd; --bg:#faf9f8; }
* { box-sizing: border-box; }
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; color: var(--ink); margin: 0; background: #fff; }
.classification { background: var(--ink); color: #fff; text-align: center; font-size: 12px; letter-spacing: 2px; text-transform: uppercase; padding: 4px 0; }
header { padding: 28px 40px 18px; border-bottom: 3px solid var(--ink); }
header h1 { margin: 0 0 4px; font-size: 26px; }
header .meta { color: var(--muted); font-size: 13px; }
main { padding: 24px 40px 40px; max-width: 1180px; }
h2 { font-size: 19px; border-bottom: 1px solid var(--line); padding-bottom: 6px; margin-top: 34px; }
h3 { font-size: 15px; margin-top: 24px; }
p, li, td, th { font-size: 13.5px; line-height: 1.55; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; }
th { text-align: left; background: var(--bg); border-bottom: 2px solid var(--line); padding: 7px 10px; }
td { border-bottom: 1px solid var(--line); padding: 7px 10px; vertical-align: top; }
.badge { display: inline-block; padding: 1px 9px; border-radius: 10px; color: #fff; font-size: 11.5px; font-weight: 600; }
.badge.Critical { background: var(--critical); } .badge.High { background: var(--high); }
.badge.Medium { background: var(--medium); } .badge.Low { background: var(--low); }
.badge.None { background: var(--na); }
.badge.Pass { background: var(--pass); } .badge.Fail { background: var(--critical); }
.badge.Partial { background: var(--medium); } .badge.NotAssessed { background: var(--na); }
.badge.Informational { background: var(--low); }
.bar-track { background: var(--bg); border: 1px solid var(--line); border-radius: 4px; height: 16px; width: 220px; display: inline-block; vertical-align: middle; }
.bar-fill { height: 100%; border-radius: 3px; background: var(--pass); }
.kpi-row { display: flex; gap: 18px; flex-wrap: wrap; margin: 18px 0; }
.kpi { border: 1px solid var(--line); border-radius: 8px; padding: 14px 20px; min-width: 160px; background: var(--bg); }
.kpi .value { font-size: 30px; font-weight: 700; }
.kpi .label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }
.evidence { color: var(--muted); }
footer { padding: 16px 40px 30px; color: var(--muted); font-size: 11.5px; border-top: 1px solid var(--line); }
@media print { main { padding: 12px 0; } header { padding: 12px 0; } .no-print { display: none; } }
</style>
</head>
<body>
<div class="classification">$classification</div>
<header>
<h1>$(& $encode $Title)</h1>
<div class="meta">$customer$(if ($reference) { " &middot; Engagement $reference" }) &middot; Tenant $tenant &middot; Generated $generated &middot; Get-EntraZTAssess</div>
</header>
<main>
$BodyHtml
</main>
<footer>
$classification &middot; Produced by the Entra ID Security &amp; Endpoint Zero Trust Assessment toolkit. Evidence is drawn from read-only Microsoft Graph collection persisted in the run folder; findings marked NotAssessed state the reason data was unavailable.
</footer>
<div class="classification">$classification</div>
</body>
</html>
"@
}
