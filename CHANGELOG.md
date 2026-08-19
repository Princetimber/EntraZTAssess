# Changelog for Get-EntraZTAssess

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added the **SecurityCompliance** assessment module/domain (4 checks,
  SC-001 to SC-004), the second domain built on the read-only Exchange
  Online / Security & Compliance (IPPS) connection surface, alongside
  ThreatProtection:
  - `Invoke-ZTAssessSecurityComplianceCollection` collects Microsoft
    Purview retention and records-management configuration
    (`Get-RetentionCompliancePolicy`, `Get-RetentionComplianceRule`,
    `Get-ComplianceTag`) via `Invoke-ZTAssessExoRequestWrapper`. Only
    invoked when `$connection.ExchangeOnlineConnected` is true; otherwise
    a manifest warning is recorded and the module's checks degrade to
    `NotAssessed`.
  - `Test-ZTAssessSecurityCompliance` implements: SC-001 (retention
    policies cover Exchange together with SharePoint or OneDrive),
    SC-002 (retention rules retain content for at least a configurable
    minimum duration or indefinitely), SC-003 (at least one compliance
    tag is configured as a record label), and SC-004 (informational
    retention/records inventory summary).
  - New `Settings.Thresholds.RetentionRuleMinimumDurationDays` and
    `DomainWeights.SecurityCompliance`.
  - Wired into `Invoke-ZTAssessment`'s collection (gated on
    `$connection.ExchangeOnlineConnected`) and assessment phases.

- Added the **ThreatProtection** assessment module/domain (4 checks, TP-001
  to TP-004), the first domain to use the read-only Exchange Online /
  Security & Compliance (IPPS) connection surface added previously:
  - `Invoke-ZTAssessThreatProtectionCollection` collects Defender for
    Office 365 / Exchange Online Protection policy configuration
    (`Get-SafeLinksPolicy`, `Get-SafeAttachmentPolicy`,
    `Get-AntiPhishPolicy`, `Get-MalwareFilterPolicy`) via
    `Invoke-ZTAssessExoRequestWrapper`. Only invoked by
    `Invoke-ZTAssessment` when `Connect-ZTAssessment` established the
    Exchange Online / IPPS connection; otherwise a manifest warning is
    recorded and the module's checks report `NotAssessed`.
  - `Test-ZTAssessThreatProtection` implements: TP-001 (Safe Links scans
    URLs and blocks click-through), TP-002 (Safe Attachments takes a
    blocking action rather than monitor-only), TP-003 (anti-phishing
    mailbox/spoof intelligence enabled at or above a configurable
    threshold level), and TP-004 (malware filtering enables the file
    filter with a blocking action).
  - New `Settings.Thresholds.PhishThresholdMinimumLevel` and
    `DomainWeights.ThreatProtection`.
  - Wired into `Invoke-ZTAssessment`'s collection (gated on
    `$connection.ExchangeOnlineConnected`) and assessment phases.

- Added the **Defender** assessment module/domain (4 checks, DF-001 to DF-004),
  Graph-only, with no dependency on the Exchange Online / IPPS surface added
  previously:
  - `Invoke-ZTAssessDefenderCollection` collects the latest Microsoft Secure
    Score entry, secure score control profile metadata, and unified security
    alerts (`/security/secureScores`, `/security/secureScoreControlProfiles`,
    `/security/alerts_v2`).
  - `Test-ZTAssessDefender` implements: DF-001 (Secure Score meets a
    configurable maturity floor), DF-002 (Defender for Endpoint device
    onboarding coverage — a best-effort proxy via the tenant's Secure Score
    control contribution, since Microsoft Graph exposes no direct
    "onboarded machines" list; degrades to `NotAssessed` if the expected
    control cannot be found), DF-003 (open high-severity alerts triaged
    within a configurable SLA), and DF-004 (informational Secure Score
    improvement-opportunity summary).
  - New module catalogue entry in `Settings/permissions.psd1`
    (`SecurityEvents.Read.All`, `SecurityAlert.Read.All`), new
    `Settings.Thresholds.SecureScoreMinimumPercent` /
    `OpenHighSeverityAlertMaxAgeDays`, and a new `Settings.Defender.
    OnboardingControlNames` list of candidate secure score control names.
  - Wired into `Invoke-ZTAssessment`'s collection and assessment phases;
    `DomainWeights.Defender` added to `settings.psd1`.

- Added a second, read-only connection surface for Exchange Online / Security
  & Compliance (IPPS), established lazily by `Connect-ZTAssessment` alongside
  Microsoft Graph, for assessment modules whose data does not exist in Graph.
  All calls flow through the new `Invoke-ZTAssessExoRequestWrapper`, which
  only permits an explicit allow-list of `Get-*` cmdlets
  (`Get-ZTAssessExoAllowedCmdletName`); the Exchange Online / IPPS session
  itself is scoped to that same allow-list via `-CommandName`. This surface
  reuses the same certificate as the existing app-only Graph connection, is
  skipped for delegated/device-code sign-in, and never fails the overall
  connection — a failure or skip degrades dependent checks to `NotAssessed`
  the same way a Graph collector failure already does.
  - `Connect-ZTAssessment` gains an optional `-Organization` parameter and an
    `ZTASSESS_ORGANIZATION` environment variable / `auth.json` `Organization`
    key, resolved (in order) from the explicit parameter, the environment
    variable, `auth.json`, a domain-looking `-TenantId`, or derived from the
    connected Graph tenant's initial verified domain.
  - The connection summary returned by `Connect-ZTAssessment` gains
    `ExchangeOnlineConnected` and `ExchangeOnlineWarning`.
  - `Disconnect-ZTAssessment` also tears down the Exchange Online / IPPS
    session when one was established.
  - Four new module catalogue entries — `SecurityCompliance`, `Collaboration`,
    `DataProtection`, `ThreatProtection` — are added to
    `Settings/permissions.psd1` with a `RequiresExchangeOnline` flag and
    `ExchangeOnlineRoles` provisioning guidance (`Get-ZTAssessModuleCatalog`
    surfaces both). These modules are not yet implemented in
    `Invoke-ZTAssessment` (checks/collectors/assessors ship in follow-up
    phases); selecting them today only exercises the new connection surface.
  - New provisioning-only, no-network function
    `Get-ZTAssessExchangeOnlineRoleGuidance` (in the repo-local
    `EntraZTAssess.Provisioning` module) lists the Exchange Online / IPPS role
    groups a tenant's own Exchange administrator must grant; this toolkit
    never grants them itself. `Get-ZTAssessProvisioningStep` surfaces this as
    an additional step when relevant.
  - `tests/QA/ReadOnly.tests.ps1` gains four new static gates mirroring the
    existing Microsoft Graph read-only enforcement for this surface. See
    `docs/Authentication.md` for full details.

### Changed

- Added `graphify-out/` to `.gitignore`. It holds local, disposable knowledge-graph
  analysis output (`graph.json`, `graph.html`, `manifest.json`, `cache/`) generated
  by the graphify tooling and must not be tracked in the repo.

### Fixed

- Corrected the admin-consent role guidance in `docs/PermissionsGuidance.md`,
  `docs/Authentication.md`, `README.md`, and `scripts/README.md`, which
  stated that granting the CBA app's Application permissions requires
  Global Administrator. All of these permissions are Microsoft Graph
  application permissions, and Microsoft reserves consent to those to
  **Privileged Role Administrator** (Global Administrator also qualifies,
  but is not the least-privileged option); Application Administrator and
  Cloud Application Administrator — while sufficient to register the app
  and add the requested app roles — are explicitly excluded from consenting
  to Microsoft Graph application permissions. Tenants that will not grant
  Global Administrator can still complete provisioning with a time-bound
  Privileged Role Administrator assignment for the consent step only.
- Added `.vscode/settings.json` (project-scoped, checked in) pinning the
  PowerShell extension's `codeFormatting.preset` to `OTBS` with
  `openBraceOnSameLine: true`, plus `alignPropertyValuePairs`,
  `addWhitespaceAroundPipe`, `useCorrectCasing`, `autoCorrectAliases`, and
  `pipelineIndentationStyle` to mirror `PSScriptAnalyzerSettings.psd1`, and
  `powershell.scriptAnalysis.settingsPath` to point live diagnostics at the
  project ruleset instead of the extension's defaults. Without this, a
  contributor's personal VS Code settings could disagree with
  `PSScriptAnalyzerSettings.psd1` and "Format Document"/format-on-save would
  silently revert the repo's own OTBS fix on save — this happened twice in
  one session before the personal `settings.json` was corrected; this file
  makes the correct config the per-workspace default for every contributor.
- Raised the `RequiredModules.psd1` lower bound for `PSScriptAnalyzer` from
  `1.22` to `1.25.0`. `1.24.0` has a flaky `NullReferenceException` inside
  `Invoke-ScriptAnalyzer` when enough `Rules` entries in
  `PSScriptAnalyzerSettings.psd1` are active simultaneously — reproduced
  locally (~1 crash in 5 runs against `Export-ZTAssessReport.ps1`) and seen
  failing CI's Ubuntu/Windows test jobs while macOS passed, since CI restores
  a fresh dependency set per run and could land on the buggy version.
  `1.22.0`/`1.23.0` were not individually verified; the lower bound was
  raised straight to the confirmed-clean `1.25.0` rather than bisecting
  further.
- Reformatted the remaining 32 `source/` files (the module root `Get-EntraZTAssess.psm1`
  plus 31 `source/Private/` functions, most notably the large domain assessors
  `Test-ZTAssessEndpointManagement.ps1`, `Test-ZTAssessIdentitySecurity.ps1`,
  `Test-ZTAssessPrivilegedAccess.ps1`, and `Test-ZTAssessConditionalAccess.ps1`)
  via `Invoke-Formatter` under the corrected OTBS settings, resolving the
  remaining `PSPlaceCloseBrace` (255 → 3) and `PSUseConsistentIndentation`
  (129 → 90) findings from a full `source/ -Recurse` sweep. Brace cuddling
  only, no logic changes. The 3 remaining `PSPlaceCloseBrace` and 90 remaining
  `PSUseConsistentIndentation` findings are confined entirely to
  `Get-EntraZTAssess.psd1`, whose flush-left, unindented layout is the
  standard `New-ModuleManifest`-generated manifest convention and is left
  as-is, consistent with the existing `PSAlignAssignmentStatement` `.psd1`
  exemption documented above. These 32 files are all `Private/` functions
  not covered by `tests/QA/module.tests.ps1`'s exported-function lint loop,
  so this was a quality-debt cleanup, not a CI-gating fix.
- `PSScriptAnalyzerSettings.psd1`'s `PSPlaceOpenBrace.OnSameLine` corrected
  from `$false` to `$true`. The prior value enforced Allman-style bracing
  (opening brace always on its own line) while the settings file's own
  header and inline comment both documented the intent as OTBS ("One True
  Brace Style"), which keeps the opening brace on the statement's line and
  cuddles `else`/`catch`/`finally` with the preceding closing brace. Running
  `Invoke-Formatter` under the old value would have reformatted the entire
  `source/` tree into Allman style; caught before any files were reformatted.
- `PSScriptAnalyzerSettings.psd1`'s `PSUseConsistentWhitespace.CheckOperator`
  disabled (`$true` → `$false`). It enforces exactly one space around `=`,
  which directly conflicts with `PSAlignAssignmentStatement`'s padded
  alignment of hashtable/splat assignments — the two rules could never both
  pass on an aligned hashtable, so every `Invoke-Formatter` pass over an
  aligned splat left one of the two rules failing. Disabling `CheckOperator`
  forgoes single-space enforcement around all binary/assignment operators
  project-wide in favour of keeping hashtable/splat alignment enforced and
  auto-fixable via `Invoke-Formatter`.
- Reformatted the 10 public functions that were failing
  `tests/QA/module.tests.ps1`'s `Should pass Script Analyzer for <Name>`
  check (`Connect-ZTAssessment`, `Disconnect-ZTAssessment`,
  `Export-ZTAssessReport`, `Get-ZTAssessFinding`,
  `Get-ZTAssessModuleCatalog`, `Get-ZTAssessProvisioningStep`,
  `Get-ZTAssessRequiredPermission`, `Get-ZTAssessScore`,
  `Invoke-ZTAssessment`, `New-ZTAssessEngagement`) via `Invoke-Formatter`
  under the corrected settings above — brace cuddling and hashtable
  re-alignment only, no logic changes. Full `Invoke-Pester -Path tests` run
  green (489 passed, 1 pre-existing skip) after the fix.
- `Get-ZTAssessRetryDelay` now returns `0.0` instead of the integer literal
  `0` on its no-`Retry-After`-header path, matching its declared
  `[OutputType([double])]` instead of silently returning `System.Int32`.
- `Get-ZTAssessSnapshot`'s `[OutputType]` widened from `[object]` to
  `[object[]]` to match its actual `, $parsed` array-preserving return.
- `Get-ZTAssessDeviceClass` and `Get-ZTAssessPlatformProfile` now build their
  internal result lists as strongly-typed
  `List[pscustomobject]`/`List[ZTAssessPlatformProfile]` instead of
  `List[object]`; their `[OutputType]` attributes are declared as
  `[object[]]` to match the `, $x.ToArray()` array-preserving return idiom,
  which PSScriptAnalyzer statically types as `object[]` regardless of the
  underlying element type.
- `Protect-ZTAssessReportUserIdentifierString` (private helper in
  `Protect-ZTAssessReportUserIdentifier.ps1`) now declares
  `[OutputType([string])]`, matching its actual return type.

### Security

- `New-ZTAssessAppRegistration` (`EntraZTAssess.Provisioning`) no longer
  requests `AppRoleAssignment.ReadWrite.All` or `Directory.Read.All` for the
  provisioning sign-in unless `-GrantAdminConsent` is supplied, closing an
  over-broad, unconditional consent-scope request that violated the project's
  least-privilege default.
- `New-ZTAssessAppRegistration` now refuses to silently create a duplicate
  application registration when one with the same `-DisplayName` already
  exists, stopping with the existing application's `AppId` unless `-Force`
  is supplied. Previously, a rerun created a second app + service principal
  and silently overwrote `~/.ztassess/auth.json`, orphaning the first
  application's consent grants.
- The interactive `Connect-MgGraph` sign-in in `New-ZTAssessAppRegistration`
  is now gated by `ShouldProcess`, so `-WhatIf` no longer performs a sign-in
  that could create or refresh a delegated consent grant.
- Failed app-role grant attempts during `-GrantAdminConsent` are now surfaced
  via a `FailedGrants` property on the returned summary object, instead of
  only a console warning that was lost from the return value.
- `New-ZTAssessCertificate`'s `-InstallToWindowsStore` now round-trips the
  certificate through its exported PFX bytes with `PersistKeySet |
  Exportable` before adding it to `CurrentUser\My`, so the store copy
  reliably retains a usable private key instead of depending on
  `X509Store.Add` persisting an ephemeral key on every .NET/OS combination.
- `New-ZTAssessCertificate` now restricts its output directory (`0700`) and
  exported `.pfx` (`0600`) to the owner on macOS/Linux after writing them.
- `New-ZTAssessAppRegistration` now sets `ConfirmImpact = 'High'` on its
  `SupportsShouldProcess` binding, so `-Confirm` prompts by default under the
  default confirmation preference for this Graph-write, app-registration
  cmdlet. Its help now also documents that a transient Graph 429/503 during
  provisioning should be resolved by rerunning the function, using `-Force`
  if a partial application registration was already created.

### Added

- A repo-root `PSScriptAnalyzerSettings.psd1` (excluding
  `PSUseBOMForUnicodeEncodedFile`, a Windows-legacy concern not applicable to
  PS7+ on macOS/Linux). `tests/QA/module.tests.ps1` now passes it to
  `Invoke-ScriptAnalyzer`, matching project convention for running the linter
  with an explicit settings file.
- Additional Pester coverage for `EntraZTAssess.Provisioning`: the unmatched
  Application-app-role warning path, the zero-resolved-roles throw, the
  `.pfx`-sibling `CertificatePath` preference, USGov/China admin-consent host
  URLs, and `-SubjectName`/`-ValidityMonths` parameter validation.

### Fixed

- `New-ZTAssessAppRegistration`'s `TenantId` parameter now validates that the
  value is a GUID or a domain-shaped string, failing fast with an actionable
  message instead of a less-actionable error from inside `Connect-MgGraph`.
- `New-ZTAssessAppRegistration` now prefers the non-obsolete
  `X509CertificateLoader.LoadCertificateFromFile` API when available on the
  host .NET runtime, falling back to the `X509Certificate2` path constructor
  (marked obsolete as `SYSLIB0057`) on older runtimes.
- Simplified `New-ZTAssessCertificate`'s PFX-password handling to remove a
  confusing self-assignment no-op (`$pfxPassword = $PfxPassword`, a no-op
  under PowerShell's case-insensitive variable names).

- Dependency restore now rejects `Microsoft.PowerShell.PSResourceGet` versions
  older than 1.2.0 before they can fail on PSGallery V2 repository metadata,
  surfacing an actionable update message instead of the cross-platform
  `Requested value 'V2'` exception.
- Bumped the pinned `PSResourceGetVersion` in `Resolve-Dependency.psd1` from
  `1.0.1` to `1.2.0` so the PSResourceGet fallback (used when the ModuleFast
  bootstrap script cannot be downloaded, for example when `bit.ly/modulefast`
  responds with an interstitial HTML page) installs a version that satisfies
  the new minimum-version gate instead of immediately throwing.
- Tightened the `InvokeBuild` constraint in `RequiredModules.psd1` from
  `[5.0,6.0)` to `[5.10.5,6.0)` so the build no longer caches the pre-PS 7.4
  releases that fail with
  `A parameter with the name 'ProgressAction' was defined multiple times`
  (Invoke-Build issue #183). `build.ps1` also defensively removes
  `ProgressAction` from `$PSBoundParameters` before splatting into
  `Invoke-Build`, which unblocks workspaces that still have an older cached
  copy under `output/RequiredModules/InvokeBuild/`.
- Realigned the `Sampler.GitHubTasks` constraint in `RequiredModules.psd1`
  from `[0.6,1.0)` to `[0.4.1,1.0)` so dependency restore stops emitting
  `Save-PSResource: Package(s) 'Sampler.GitHubTasks' could not be installed
  from repository 'PSGallery'` on every build. PSGallery's latest published
  version is `0.4.1`; the prior lower bound was unsatisfiable.
- Switched the ModuleFast bootstrap URI in `Resolve-Dependency.ps1` from the
  schemeless `bit.ly/modulefast` shortlink to the canonical raw GitHub URL
  `https://raw.githubusercontent.com/JustinGrote/ModuleFast/main/ModuleFast.ps1`,
  with `bit.ly/modulefast` retained as a fallback. The bit.ly shortlink served
  a 560 KB interstitial HTML page over HTTP on some networks, which caused
  `[ScriptBlock]::Create(...)` to throw the noisy
  `html, ... Missing argument in parameter list` warning at the start of every
  build. The fallback loop also validates that the downloaded body is not HTML
  before handing it to the parser.
- Corrected the ModuleFast specification format in `Resolve-Dependency.ps1` so
  NuGet-range values from `RequiredModules.psd1` (e.g. `[0.118,1.0)`) are
  emitted as `Module:[range]` instead of `Module[range]`. ModuleFast 1.x reads
  the colonless form as a single package id and fails the
  `pwsh.gallery/registration/<name>/index.json` lookup with
  `Sampler[0.118,1.0): module was not found in the https://pwsh.gallery/index.json repository`.
  The fix preserves the existing prerelease (`!`) and pre-colonized
  (`:[...]`) spec values untouched.
- Hardened the ModuleFast bootstrap path in `Install-BuildDependency.ps1` so
  it tries the canonical raw GitHub URL first, decodes `Invoke-WebRequest`
  responses delivered as `byte[]` (the default on Windows PowerShell), and
  rejects HTML interstitials before handing the body to
  `[ScriptBlock]::Create`. On Windows the previous code raised
  `Unexpected token '115' in expression or statement` because the response
  body was the raw byte array of `using namespace System...` rendered as
  space-separated numeric tokens. The PSGallery `Install-Module` fallback is
  retained for environments where every bootstrap URI fails.

### Changed

- `Connect-ZTAssessment` now defaults to certificate-based, app-only
  authentication (CBA) and falls back to interactive delegated sign-in only
  when no CBA configuration is found. The Quick Start continues to work with
  zero authentication arguments.

### Added

- Certificate-based, app-only authentication (CBA) as the **default** for
  `Connect-ZTAssessment`, with automatic fallback to interactive delegated
  sign-in when no CBA configuration is found. CBA settings resolve from
  explicit parameters, then environment variables (`ZTASSESS_TENANTID`,
  `ZTASSESS_CLIENTID`, `ZTASSESS_CERT_THUMBPRINT`, `ZTASSESS_CERT_PATH`,
  `ZTASSESS_ENVIRONMENT`), then the non-secret file `~/.ztassess/auth.json`.
  If a CBA configuration is present but the connection fails, the error
  surfaces rather than silently falling back.
- New `Connect-ZTAssessment` parameters: `-CertificatePath` (cross-platform
  PFX), `-CertificatePassword` (`SecureString`, never persisted), and
  `-NoInteractiveFallback` (forces a hard failure for headless/CI when no
  configuration is found). Existing `-ClientId` / `-CertificateThumbprint`
  (Windows certificate store) remain. Parameter sets: `Auto` (default),
  `AppOnlyThumbprint`, `AppOnlyCertificate`, `Delegated`.
- `EntraZTAssess.Provisioning` — a repo-local, admin-run provisioning module
  (not shipped by `Install-Module`) that exposes two advanced functions. The
  provisioning workflow is `Import-Module ./scripts/EntraZTAssess.Provisioning`
  followed by the function calls:
  - `New-ZTAssessCertificate` creates a platform-agnostic self-signed
    certificate via .NET `CertificateRequest`, producing `EntraZTAssess.cer`
    and `EntraZTAssess.pfx`.
  - `New-ZTAssessAppRegistration` creates the read-only assessment app, grants
    the read-only Application permissions (app roles resolved at runtime),
    emits the admin-consent URL by default (or grants consent programmatically
    with `-GrantAdminConsent`), and writes `~/.ztassess/auth.json`. Its own
    elevated setup permissions (`Application.ReadWrite.All`,
    `AppRoleAssignment.ReadWrite.All`, `Directory.Read.All`) are setup-only and
    are not assessment scopes.
- `Get-ZTAssessProvisioningStep` — a read-only core cmdlet (no Graph calls)
  that lists the ordered provisioning commands as discoverable, Get-Help-able
  guidance.
- `docs/Authentication.md` — authentication methods and precedence, the
  four-step CBA setup, cross-platform certificate guidance, the read-only
  Application-permissions table, the elevated one-time setup permissions,
  the `~/.ztassess/auth.json` schema, and CI/headless usage.
- `Install-BuildDependency.ps1` bootstrap guard at the repository root that
  conditionally installs the build modules declared in `RequiredModules.psd1`
  when they are not already present on the machine, including **InvokeBuild**
  and **PSScriptAnalyzer**. ModuleFast still uses its official bootstrap script
  with a PSGallery `Install-Module` fallback; the remaining modules install
  from PSGallery using declared version ranges where possible so a missing
  module or script analyzer does not cascade into a confusing `Invoke-Build`
  command-not-found failure.
- Added agentic iteration-limit guidance to `AGENTS.md`, `CLAUDE.md`, and `.github/copilot-instructions.md` so autonomous request handling stops at documented planning, retry, and verification bounds.
- Phase 5 delivery readiness hardening:
  - Consultant runbook and permissions guidance under `docs/` for scoped,
    read-only assessment delivery.
  - `Export-ZTAssessReport -RedactUserIdentifiers` option for client-safe
    report artifacts while preserving source run evidence unchanged.
  - Manifest metadata polish for PowerShell Core compatibility and gallery
    discovery tags.
  - CI ScriptAnalyzer installation pinned to a concrete version.
- Phase 4 reporting MVP:
  - Public `Export-ZTAssessReport` command for completed local run folders.
  - Deterministic local report artifacts under `<RunPath>/Reports`:
    `ExecutiveReport.html`, `TechnicalReport.html`, `RiskRegister.json`,
    `RiskRegister.csv`, and `RemediationRoadmap.json`.
  - Risk-register and remediation-roadmap generation for Fail/Partial
    findings only, using `settings.psd1` remediation SLAs (Critical 7 days,
    High 30, Medium 90, Low 180) and deterministic CSV array flattening.
  - Report helper coverage for optional run manifest, platform profile, and
    device classification artifacts; missing required findings/scores files;
    HTML encoding; NotAssessed appendix treatment; and `-WhatIf` no-write
    behavior.
- Orchestrator integration tests for the Phase 3 modules: collection mocks
  for the governance, application, hybrid, and monitoring collectors, a
  25-finding run across the four new domains, and a full 92-finding run
  across all eight implemented modules.

- Documentation maintenance rule in CLAUDE.md, AGENTS.md, and
  .github/copilot-instructions.md: every change must update the .md
  documentation set (changelog, agent files, README) in the same branch and
  commit series, and record new design assumptions where they are made.
- Malformed-record guards in the identity and privileged access assessors:
  by-id lookups now skip records with null or blank IDs per the
  graceful-degradation architecture rule, matching the existing guards in
  the privileged access lookup tables.
- Phase 2 endpoint core for the Entra ID Security & Endpoint Zero Trust
  Assessment toolkit:
  - 32 new declarative checks: DeviceTrust DT-001..004, EndpointManagement
    EM-001..007 plus platform checks AND-001..004, IOS-001..004,
    MAC-001..003, WIN-001..003, ByodGovernance BG-001..004, and
    CorporateDeviceGovernance CG-001..003 (check library now 67 checks).
  - Device collector covering Intune managed devices, Entra device objects,
    compliance policies, configuration profiles, settings catalog policies
    (beta), security baselines/intents (beta), app protection policies,
    enrolment configurations, Autopilot devices and profiles, the Apple MDM
    push certificate, ABM/ADE tokens (beta), Android Enterprise binding
    (beta), threat defence connectors, and tenant device management
    settings.
  - Device classification engine (Get-ZTAssessDeviceClass): six classes -
    Corporate, BYOD, Shared, Kiosk, PAW, Unknown - with confidence levels,
    following the ownership/enrolment-profile/PAW-pattern precedence from
    the specification. PAW candidates are flagged for consultant
    confirmation, never auto-asserted.
  - Per-platform profile builder (Get-ZTAssessPlatformProfile) producing
    ZTAssessPlatformProfile objects with ownership split, enrolment
    methods, restrictions, and coverage estimates; persisted with the
    device classification to the run folder for the Phase 4 device
    enrolment and BYOD comparison reports.
  - Four new assessors: Test-ZTAssessDeviceTrust,
    Test-ZTAssessEndpointManagement, Test-ZTAssessByodGovernance, and
    Test-ZTAssessCorporateGovernance, with conditional escalations (for
    example devices-compliant-by-default while device CA is in force, and
    an expired Apple MDM push certificate, both escalate to Critical).
  - Devices module enabled in Invoke-ZTAssessment; device fixture estate
    and unit tests covering the classification engine, all four assessors,
    and the orchestrator integration.
- Phase 1 identity core for the Entra ID Security & Endpoint Zero Trust
  Assessment toolkit:
  - Declarative check library (35 checks): IdentitySecurity ID-001..012,
    ConditionalAccess CA-001..013, and PrivilegedAccess PA-001..010, each
    with severity, maturity weight, Zero Trust pillar tags, rationale,
    remediation guidance, and Microsoft Learn references.
  - Check infrastructure: Get-ZTAssessCheckDefinition (cached library
    loader with schema validation) and New-ZTAssessFinding (factory merging
    check metadata with assessment outcomes, including conditional severity
    escalation).
  - Collectors: core tenant data (organisation, SKUs, domains, users with
    signInActivity fallback, groups), identity (registration details,
    authentication methods policy, security defaults, legacy sign-in
    aggregation - counts only, never raw sign-ins), Conditional Access
    (policies, named locations, authentication strengths), and privileged
    access (role definitions/assignments, PIM schedules, role management
    policies, service principals), all via a shared graceful-degradation
    collection runner.
  - Assessors: Test-ZTAssessIdentitySecurity, Test-ZTAssessConditionalAccess,
    and Test-ZTAssessPrivilegedAccess - pure functions over persisted
    snapshots implementing all 35 checks with NotAssessed degradation for
    missing permissions, licences, or snapshots.
  - Scoring engine (Measure-ZTAssessScore): weighted domain maturity
    scores, Zero Trust pillar scores, overall maturity with six-level
    banding, InsufficientData handling, and a separate risk posture where
    any Critical finding caps the posture at "At Risk".
  - Public: Invoke-ZTAssessment (run orchestrator producing findings.json,
    scores.json, and the run manifest in a timestamped run folder),
    Get-ZTAssessFinding (filterable findings reader), and Get-ZTAssessScore.
  - Test fixture helper modelling a well-configured tenant, plus unit tests
    for the check library, finding factory, all three assessors, the
    scoring engine, snapshot reader, collection runner, and the new public
    functions.
- Phase 0 foundations for the Entra ID Security & Endpoint Zero Trust
  Assessment toolkit:
  - Classes: ZTAssessFinding (standard finding object with validation),
    ZTAssessPlatformProfile (per-platform device assessment profile), and
    ZTAssessRunManifest (evidence-chain run manifest).
  - Settings/settings.psd1 — engagement thresholds, Graph retry behaviour,
    redaction denylist, maturity bands, domain weights, and remediation SLAs.
  - Settings/permissions.psd1 — assessment module catalogue mapping each
    module to its least-privilege, read-only Microsoft Graph scopes.
  - Public: Connect-ZTAssessment (delegated, device code, and app-only
    certificate authentication with least-privilege scope computation and
    granted-scope validation), Disconnect-ZTAssessment,
    Get-ZTAssessModuleCatalog, Get-ZTAssessRequiredPermission, and
    New-ZTAssessEngagement (engagement folder and settings scaffolding).
  - Private: Invoke-ZTAssessGraphRequest (GET-only Graph helper with
    @odata.nextLink paging, 429 Retry-After handling, and exponential
    backoff), Get-ZTAssessConfiguration (cached configuration loader),
    Protect-ZTAssessData (recursive snapshot redaction),
    New-ZTAssessRunManifest, Save-ZTAssessRunManifest, Save-ZTAssessSnapshot,
    Get-ZTAssessHttpStatusCode, Get-ZTAssessRetryDelay, and mockable
    wrappers for the Microsoft Graph SDK (Connect/Disconnect/Get-MgContext/
    Invoke-MgGraphRequest) and Start-Sleep.
  - tests/QA/ReadOnly.tests.ps1 — static QA gate enforcing the read-only
    guarantee (no Graph calls outside the GET-only wrapper, no write HTTP
    methods, no Invoke-Expression, no hard-coded secrets, and no write
    scopes in the permissions catalogue).
  - Unit tests for all new public and private functions and classes.
- Get-LogFilePath private function — returns the current module-scoped log file
  path ($script:LogFile) for inspection or use in external scripts.
- Invoke-LogRotation private function — rotates log files by shifting numbered
  backups up (log.4 removed, log.3 → log.4, …, log → log.1). Called inside the
  Write-ToLog mutex; not intended for direct use.
- Set-LogFilePath private function — sets the module-scoped log file path with
  absolute-path validation; -Force creates the destination directory on demand.
  Also updates $Global:LogFile for backward compatibility.

### Fixed

- PrivilegedAccess assessment now skips malformed principal snapshot records with null or blank IDs before building users, groups, and service principals lookup tables, preventing partial snapshots from throwing during assessment; regression coverage now exercises malformed user snapshots.
- Path parameter usability (found during the first live tenant test):
  New-ZTAssessEngagement now resolves tilde and relative paths and creates
  the output folder when it does not exist; Invoke-ZTAssessment,
  Get-ZTAssessFinding, and Get-ZTAssessScore resolve their path parameters
  and fail with actionable errors (for example 'run New-ZTAssessEngagement
  first') instead of opaque validation-script failures.
- Dependency resolution: enabled ModuleFast in Resolve-Dependency.psd1 so
  the NuGet version-range syntax in RequiredModules.psd1 (for example
  '[3.0,4.0)') resolves correctly; PowerShellGet v2 fails on version
  ranges with 'Cannot convert value to type System.Version'.

### Changed

- Clarified Phase 3 supported-module configuration by documenting public module names alongside their internal check/settings domains.
- Renamed the logger mutex and default log file prefix from the inherited
  Invoke-ADDSDomainController naming to Get-EntraZTAssess.
- Rebuilt Write-ToLog as a production-grade, thread-safe logging framework:
  - Named mutex (Global\Get-EntraZTAssessLog) prevents concurrent write
    corruption across threads and runspaces.
  - Auto-rotates at 10 MB, keeping up to 5 numbered backup files.
  - Redacts passwords, tokens, keys, and secrets in key=value, JSON, and XML/HTML
    formats before writing.
  - ANSI colour console output via PSStyle (7.2+) with escape-code fallback.
  - Dedicated ErrorRecord parameter set for structured exception logging.
  - Wrapper functions (Test-PathWrapper, Add-ContentWrapper, Get-ItemWrapper,
    New-ItemDirectoryWrapper) isolate I/O calls for Pester mockability.
  - Mutex is disposed on PowerShell exit via Register-EngineEvent.
- Pinned dependency versions in RequiredModules.psd1 using version ranges instead
  of 'latest'.
- Consolidated AI agent documentation: removed .github/instructions/ directory
  (5 files) and tests/tests.instructions.md, trimmed copilot-instructions.md.
- Updated README, CLAUDE.md, and help text to reflect all changes.

### Removed

- Unused private functions and their tests: Clear-LogFile, Get-LogFileSize,
  and Write-ErrorLog (Write-ToLog -ErrorRecord already covers error logging).
- Windows PowerShell 5.1 test job from azure-pipelines.yml (contradicts PS 7.0
  requirement in #Requires).
- .github/instructions/ directory and tests/tests.instructions.md.
- Classes/ directory reference from documentation (directory did not exist).
