# Changelog for Get-EntraZTAssess

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Documented in `docs/Authentication.md` exactly where each Exchange
  Online / Security & Compliance role in the guidance table is actually
  assigned - `View-Only Configuration` and `View-Only Recipients` in the
  Exchange admin center; `View-Only Retention Management` and
  `View-Only DLP Compliance Management` only in the Microsoft Purview
  compliance portal (they don't exist in the EAC at all), and only via
  a `Connect-IPPSSession`, not a plain Exchange Online session.
- Clarified in `docs/Authentication.md` and `README.md` that
  `Grant-ZTAssessExchangeOnlineRole` (and the rest of the "CBA Setup"
  provisioning steps) applies only to app-only (CBA) engagements. It
  authorizes the app registration's own service principal, but
  device-code mode (`Connect-ZTAssessment -UseDeviceCode`) never
  connects as an app - both its Graph and Exchange Online / IPPS
  sign-ins authenticate as the signed-in consultant, so this step is
  skipped entirely for a device-code engagement. What matters instead
  is whether the consultant's own account already holds the equivalent
  Exchange Online / Security & Compliance permissions.

## [0.3.2] - 2026-08-21

### Fixed

- `Connect-ZTAssessment -UseDeviceCode` still printed no device-code
  prompt after the 0.3.1 fix, confirmed against a live tenant - the
  Graph sign-in still timed out after ~120 seconds with nothing shown.
  The 0.3.1 fix made `Connect-MgGraphWrapper`'s own call to
  `Connect-MgGraph` bare, but `Connect-ZTAssessment`'s call to
  `Connect-MgGraphWrapper` was then changed to `$null = ...` as a
  "safety net" - which re-discarded the exact same value one frame
  later, before it could ever reach the console. `$null = ...` and
  `| Out-Null` don't just consume a pipeline, they discard it without
  rendering anything, so capturing at ANY point between the cmdlet and
  the console silently swallows the prompt, no matter how many levels
  deeper were left bare. `Connect-MgGraphWrapper` now pipes the
  device-code call to `Out-Host` instead, which renders immediately at
  that exact point and produces no output of its own - so the prompt
  displays and nothing leaks into either function's return value,
  regardless of what any caller does with it afterwards.

## [0.3.1] - 2026-08-21

### Fixed

- `Connect-ZTAssessment -UseDeviceCode` printed nothing to the console when
  signing in - no "To sign in, use a web browser..." prompt appeared at
  all, leaving the connection to eventually fail with an inactivity
  timeout. `Connect-MgGraphWrapper` (`source/Private/Connect-MgGraphWrapper.ps1`)
  captured `Connect-MgGraph`'s return value with `$null = ...` unconditionally;
  on affected `Microsoft.Graph.Authentication` SDK versions the device-code
  prompt is emitted through the same stream as the cmdlet's return value
  rather than reliably via `Write-Host`, so capturing it - even into
  `$null` - silently swallows the prompt. Confirmed by a Microsoft
  maintainer and tracked as an open SDK defect
  ([msgraph-sdk-powershell#1403](https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/1403#issuecomment-1191685915),
  [#2798](https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/2798)).
  `Connect-MgGraphWrapper` now invokes `Connect-MgGraph` fully bare (no
  capture) specifically for the device-code path; `Connect-ZTAssessment`
  already retrieves the resulting context separately via
  `Get-MgContextWrapper`, so no return value was ever needed there.
- `.github/workflows/release.yml`'s `Publish` job ran `./build.ps1 -tasks publish`,
  but `build.yaml` defines no task named `publish` — only `publish_psgallery`
  and `publish_github` — so the job has failed on every tagged release to
  date (`v0.2.0`, `v0.2.1`), with those versions actually reaching PSGallery
  only via a manual local publish afterwards. Changed to
  `-tasks publish_psgallery`; GitHub release creation is left to the
  workflow's separate `softprops/action-gh-release` step, which already
  covers it.

## [0.3.0] - 2026-08-21

### Added

- `Connect-ZTAssessment` can now establish the Exchange Online / Security &
  Compliance (IPPS) connection when Microsoft Graph itself authenticated via
  `-UseDeviceCode`, instead of always skipping it. `Connect-IPPSSession` has
  no device-code switch of its own (unlike `Connect-ExchangeOnline`), so a
  separate OAuth device-code flow (RFC 8628, plain `Invoke-RestMethod`
  calls against the Microsoft identity platform - no new module dependency)
  obtains an access token for the Exchange Online resource, which is then
  passed to both surfaces via their `-AccessToken` parameter. The default
  client ID (`Settings/settings.psd1` → `ExchangeOnline.DeviceCodeClientId`)
  is the well-known Microsoft first-party "Microsoft Exchange REST API
  Based PowerShell" public client that `Connect-ExchangeOnline -Device`
  already uses internally, so this requires no new app registration, no
  public-client-flow toggle, and no `Exchange.ManageAsApp` grant. Tenants
  whose Conditional Access policy blocks sign-in by well-known native
  client IDs can override `ExchangeOnline.DeviceCodeClientId` (and
  `DeviceCodeScope`) with their own registered public-client app. Plain
  interactive delegated sign-in (no `-UseDeviceCode`) is unchanged and
  still skips the Exchange Online / IPPS surface. `-Organization` is now
  also accepted alongside `-UseDeviceCode` (previously only available for
  the app-only and auto parameter sets), since it can no longer be resolved
  from a certificate-based auth config in this mode.

### Fixed

- `EntraZTAssess.Provisioning` 0.1.3: fixed `Get-ZTAssessExchangeOnlineRoleGuidance`
  throwing `Permission catalogue not found` for anyone who installed the
  module from PSGallery (`Install-Module EntraZTAssess.Provisioning`). Like
  the `New-ZTAssessAppRegistration` bug fixed in 0.1.1, the function
  resolved the catalogue via a dev-checkout-relative path
  (`../../../source/Settings/permissions.psd1`), which only exists inside a
  git clone of this repository - never inside an installed module. It now
  resolves the same bundled copy at `Settings/permissions.psd1` that
  `New-ZTAssessAppRegistration` already uses.
- `EntraZTAssess.Provisioning` 0.1.2: `New-ZTAssessAppRegistration` failed to
  connect to Microsoft Graph on tenants whose Conditional Access policy
  blocks interactive browser sign-in, and separately threw `A parameter
  cannot be found that matches parameter name 'NoWelcome'` on older
  installed `Microsoft.Graph.Authentication` releases that predate that
  parameter. Added a `-UseDeviceCode` switch (mirrors `Connect-ZTAssessment`)
  to request the OAuth device-code flow for this function's one-time
  interactive setup sign-in, and `-NoWelcome` is now only added to the
  `Connect-MgGraph` call when the installed cmdlet actually declares it.
- `EntraZTAssess.Provisioning` 0.1.1: fixed `New-ZTAssessAppRegistration`
  throwing `Permission catalogue not found` for anyone who installed the
  module from PSGallery (`Install-Module EntraZTAssess.Provisioning`). The
  function resolved the catalogue via a dev-checkout-relative path
  (`../../../source/Settings/permissions.psd1`), which only exists inside a
  git clone of this repository - never inside an installed module. The
  module now bundles its own copy at `Settings/permissions.psd1` (declared
  in the manifest `FileList`) and resolves it relative to its own root.

### Changed

- Updated `CLAUDE.md` to document: the ModuleFast → PSResourceGet automatic
  fallback in `./build.ps1 -ResolveDependency`; the `Private/` folder and
  platform-helper pattern in `EntraZTAssess.Provisioning`; and the rule that
  platform-conditional tests must mock private helpers with `-ModuleName`
  rather than guarding with `-Skip:$IsWindows`.

### Fixed

- Reformatted `scripts/EntraZTAssess.Provisioning`'s `Public/` and `Private/`
  function files with `Invoke-Formatter` against the project's
  `PSScriptAnalyzerSettings.psd1` — resolves 77 pre-existing style warnings
  (brace placement, indentation, single- vs double-quote usage). No
  behavioral change; `tests/Unit/Provisioning` still passes unchanged.

### Added

- Published `EntraZTAssess.Provisioning` as its own, separately versioned
  PSGallery package (`Install-Module EntraZTAssess.Provisioning`), so admins
  no longer have to clone this repository to run the one-time provisioning
  commands (`New-ZTAssessCertificate`, `New-ZTAssessAppRegistration`,
  `Get-ZTAssessExchangeOnlineRoleGuidance`, `Grant-ZTAssessExchangeOnlineRole`).
  It remains outside `Get-EntraZTAssess`'s `Install-Module` surface — this
  toolkit's read-only guarantee is unaffected, since the write-capable
  provisioning code still lives in a distinct package the assessment module
  never depends on. Cloning `scripts/EntraZTAssess.Provisioning` from this
  repository still works as before. Filled in the module's placeholder
  `Author`/`CompanyName`/`Copyright` and added `LicenseUri`/`ProjectUri`;
  moved `scripts/README.md` into `scripts/EntraZTAssess.Provisioning/README.md`
  so it packages as the PSGallery readme.

## [0.2.1] - 2026-08-19

### Added

- Filled in the MIT `LICENSE` copyright holder (was a template placeholder,
  `{{AUTHOR}}`) and populated the manifest's `PrivateData.PSData.LicenseUri`
  and `ProjectUri` so PSGallery shows license/project links on the package
  page.
- Added `../README.md` to `build.yaml`'s `CopyPaths` so the repo's README
  is copied into the built module root and rendered by PSGallery as the
  package readme; previously the built package shipped without one.

## [0.2.0] - 2026-08-19

### Fixed

- Enabled `New-ZTAssessCertificate` unit tests that previously skipped on
  Windows — extracted `Test-ZTAssessIsWindowsPlatform` and
  `Invoke-ZTAssessSetUnixFileMode` as private provisioning-module helpers
  so Pester can mock both instead of the tests skipping via
  `-Skip:$IsWindows`. The macOS/Linux permission and off-Windows
  `InstallToWindowsStore` warning branches are now verified on all
  platforms via module-scoped mocks.

- Fixed `./build.ps1 -ResolveDependency` failing on Windows networks where
  `pwsh.gallery:443` is blocked — `Resolve-Dependency.ps1` now catches the
  `Install-ModuleFast -Plan` network failure and falls back to PSResourceGet
  instead of rethrowing, so the dependency resolution succeeds on those
  machines. ModuleFast remains the primary resolver on CI and macOS/Linux
  where pwsh.gallery is reachable.

- Fixed `Grant-ZTAssessExchangeOnlineRole`'s dedicated-role-group fallback
  failing at the `Add-RoleGroupMember` step with `DisplayName: The
  property DisplayName can't be empty.` immediately after `New-RoleGroup`
  had just succeeded — confirmed live that `New-RoleGroup` leaves
  `DisplayName` empty when it is not supplied explicitly, and that empty
  value then fails validation on the very next write to the same object.
  `New-RoleGroup` now passes `-DisplayName` explicitly (matching `-Name`),
  which resolved the grant end-to-end on a live tenant.

- Fixed `Grant-ZTAssessExchangeOnlineRole`'s dedicated-role-group fallback
  failing with `Couldn't find object "<servicePrincipalGuid>". Please
  make sure that it was spelled correctly or specify a different
  object.` even though the identical service principal identity was
  accepted moments earlier by `Add-RoleGroupMember` for a different role
  group — confirmed live that `New-RoleGroup`'s own `-Members` parameter
  does not reliably accept a service principal identity. `New-RoleGroup`
  is now called without `-Members` to create the role group, and the
  service principal is added to it as a separate `Add-RoleGroupMember`
  call, using the mechanism already proven to work for role groups.

- Fixed `Grant-ZTAssessExchangeOnlineRole` failing to grant `View-Only
  Retention Management` and `View-Only DLP Compliance Management` with
  `The "<role>" management role can't be found. Check the role entry
  name, and try again.` — confirmed live against a real tenant that this
  error recurs identically even after the IPPS-connection retry added
  previously, meaning direct `New-ManagementRoleAssignment -App`
  assignment is simply not supported for these two management roles,
  regardless of connection. Added a fourth, final fallback mechanism
  matching Microsoft's documented workaround for this case: create (or
  reuse, on re-runs) a dedicated role group scoped to exactly that one
  management role (`New-RoleGroup -Name 'EntraZTAssess - <role>' -Roles
  '<role>' -Members <servicePrincipal>`) and add the app's service
  principal to it. `Grant-ZTAssessExchangeOnlineRole` now tries, per
  entry and in order: role-group membership, direct management-role
  assignment, the same direct assignment again via IPPS, and finally this
  dedicated-role-group workaround, stopping at the first that succeeds.

- Fixed `Grant-ZTAssessExchangeOnlineRole` failing with "The
  ExchangeOnlineManagement module is required but these commands were not
  found: Get-ServicePrincipal, New-ServicePrincipal, Get-RoleGroupMember,
  Add-RoleGroupMember, New-ManagementRoleAssignment" even when the module
  was correctly installed. Those five commands are dynamic RBAC proxy
  commands that ExchangeOnlineManagement only injects into the session
  **after** a successful `Connect-ExchangeOnline` / `Connect-IPPSSession`
  — they were being checked before connecting, alongside the genuinely
  static `Connect-ExchangeOnline` / `Connect-IPPSSession` /
  `Disconnect-ExchangeOnline` exports, so the precondition check always
  failed for them regardless of whether the module was installed. The
  precondition check is now split: `Connect-ExchangeOnline` /
  `Connect-IPPSSession` / `Disconnect-ExchangeOnline` are still verified
  before connecting, while the RBAC proxy commands are verified
  immediately after `Connect-ExchangeOnline` succeeds, with a clear error
  if they still aren't available (most likely insufficient Exchange
  Online / Security & Compliance administrative rights on the signed-in
  account). Added a regression test that reproduces the original bug by
  never stubbing those five commands and asserting the function still
  reaches `Connect-ExchangeOnline` rather than failing at the pre-connect
  check.

- Fixed a flaky `tests/QA/module.tests.ps1` failure where
  `Invoke-ScriptAnalyzer` intermittently threw a `NullReferenceException`
  from within its own rule engine on `ubuntu-latest` CI runners — observed
  against a different, otherwise lint-clean source file each time
  (confirmed pre-existing on `main`, unrelated to any particular file's
  content), so it is an environment/tool flake rather than a real lint
  violation. The `'Should pass Script Analyzer for <Name>'` test now
  retries the `Invoke-ScriptAnalyzer` call up to 3 times before treating it
  as a hard failure; a genuine lint violation is still returned as a
  diagnostic record rather than an exception, so retrying can never mask a
  real finding.

### Added

- Added `Grant-ZTAssessExchangeOnlineRole` to the repo-local
  `EntraZTAssess.Provisioning` module (`scripts/`). It optionally performs
  the Exchange Online / Security & Compliance (IPPS) role grant that
  `Get-ZTAssessExchangeOnlineRoleGuidance` previously only documented as a
  manual step for the tenant's own Exchange administrator — needed for
  `SecurityCompliance`, `Collaboration`, `DataProtection`, and
  `ThreatProtection`. It connects to Exchange Online / IPPS as the
  **calling administrator** (interactive delegated sign-in), never as the
  app being granted roles — authenticating as that app would be circular,
  since it may not yet be authorized to connect at all. It creates the
  app's Exchange Online-side service principal with `New-ServicePrincipal`
  if one does not already exist (which admin-consenting
  `Exchange.ManageAsApp` alone does **not** create), then grants each
  required catalogue entry with whichever mechanism actually matches what
  it is in the connected tenant: `Add-RoleGroupMember` for genuine role
  groups, or `New-ManagementRoleAssignment -App` for management roles.
  Verified against a live tenant across the full catalogue: `Security
  Reader` is a genuine role group; `View-Only Configuration` and
  `View-Only Recipients` are management roles visible in the Exchange
  Online session; `View-Only Retention Management` and `View-Only DLP
  Compliance Management` are management roles visible only in the
  Security & Compliance / IPPS session — despite all four reading like
  role-group names, none of them are role groups. Falls back to a
  lazily-established IPPS connection as a last resort, which is what
  resolves the two Purview-only roles. A grant that fails against every
  mechanism is recorded in `FailedGrants` rather than aborting the run. Like `New-ZTAssessAppRegistration`, it is a
  write operation and therefore lives outside the read-only `source/`
  module; it must be run by an account with sufficient Exchange Online /
  Security & Compliance administrative rights. Requires the
  `ExchangeOnlineManagement` module (declared via
  `ExternalModuleDependencies`, not a hard `RequiredModules` dependency).
  `docs/Authentication.md`, `docs/PermissionsGuidance.md`, `CLAUDE.md`,
  `AGENTS.md`, `.github/copilot-instructions.md`, and `README.md` are
  updated to describe this as an optional alternative to the manual grant,
  not a change to the assessment module's read-only guarantee.

- Added the **CloudAppSecurity** assessment module/domain (3 checks,
  CAS-001 to CAS-003), the sixth and final planned domain in this
  extension. Unlike the four EXO-backed domains, this is a **Graph-only,
  best-effort Microsoft Secure Score proxy** — Microsoft Graph exposes no
  Defender for Cloud Apps configuration API (no MCAS policies, app risk
  scores, or OAuth app governance), so this domain is explicitly scoped
  to partial coverage and documents that limitation in its own check
  metadata (CAS-003) rather than overclaiming assessment depth:
  - No separate collector: `CloudAppSecurity` shares the
    `secureScoreLatest`/`secureScoreControlProfiles` snapshots collected
    by `Invoke-ZTAssessDefenderCollection` (now invoked when either
    `Defender` or `CloudAppSecurity` is selected), and needs no Exchange
    Online / IPPS connection.
  - `Test-ZTAssessCloudAppSecurity` implements: CAS-001 (Defender for
    Cloud Apps setup shows a non-zero Secure Score contribution — a
    best-effort proxy for provisioning, matched against a configurable
    candidate control name list and degrading to `NotAssessed` if
    unmatched, mirroring the existing DF-002 pattern), CAS-002
    (Cloud-App-Security-relevant controls are not left in an `Ignored`
    state without review), and CAS-003 (informational coverage summary
    and disclaimer).
  - New module catalogue entry in `Settings/permissions.psd1`
    (`SecurityEvents.Read.All`), new `Settings.CloudAppSecurity.
    SetupControlNames` candidate list, and `DomainWeights.
    CloudAppSecurity` set lower (0.5) than fully-verified domains to
    reflect its weaker signal quality.
  - Wired into `Invoke-ZTAssessment`'s collection and assessment phases.
  - This completes the module catalogue: all 6 planned domains
    (Defender, ThreatProtection, SecurityCompliance, DataProtection,
    Collaboration, CloudAppSecurity) are now implemented.

- Added the **Collaboration** assessment module/domain (4 checks, CO-001
  to CO-004), the fourth and final Phase-1 domain built on the read-only
  Exchange Online / Security & Compliance (IPPS) connection surface,
  alongside ThreatProtection, SecurityCompliance, and DataProtection:
  - `Invoke-ZTAssessCollaborationCollection` collects Exchange external
    sharing and mail-flow configuration (`Get-SharingPolicy`,
    `Get-TransportRule`) via `Invoke-ZTAssessExoRequestWrapper`. Only
    invoked when `$connection.ExchangeOnlineConnected` is true; otherwise
    a manifest warning is recorded and the module's checks degrade to
    `NotAssessed`. SharePoint tenant sharing settings (`Get-SPOTenant`)
    are deliberately out of scope for v1 — they require a third
    connection surface (`Connect-SPOService`) this module does not
    establish.
  - `Test-ZTAssessCollaboration` implements: CO-001 (no enabled sharing
    policy grants anonymous users calendar detail or full details),
    CO-002 (no enabled transport rule silently redirects or blind-copies
    messages — a common post-compromise exfiltration technique), CO-003
    (no enabled sharing policy grants full calendar details to all
    external domains via a wildcard entry), and CO-004 (informational
    external-collaboration inventory summary).
  - New `DomainWeights.Collaboration`.
  - Wired into `Invoke-ZTAssessment`'s collection (gated on
    `$connection.ExchangeOnlineConnected`) and assessment phases.

- Added the **DataProtection** assessment module/domain (4 checks, DP-001
  to DP-004), the third domain built on the read-only Exchange Online /
  Security & Compliance (IPPS) connection surface, alongside
  ThreatProtection and SecurityCompliance:
  - `Invoke-ZTAssessDataProtectionCollection` collects Microsoft Purview
    Data Loss Prevention and sensitivity label configuration
    (`Get-DlpCompliancePolicy`, `Get-DlpComplianceRule`, `Get-Label`,
    `Get-LabelPolicy`) via `Invoke-ZTAssessExoRequestWrapper`. Only
    invoked when `$connection.ExchangeOnlineConnected` is true; otherwise
    a manifest warning is recorded and the module's checks degrade to
    `NotAssessed`.
  - `Test-ZTAssessDataProtection` implements: DP-001 (at least one DLP
    policy is enforcing, not test-only, across Exchange with
    SharePoint/OneDrive), DP-002 (at least one DLP rule blocks access on
    a sensitive-information match rather than only notifying), DP-003
    (at least one sensitivity label exists and is published via a label
    policy), and DP-004 (informational DLP/label inventory summary).
  - New `DomainWeights.DataProtection`.
  - Wired into `Invoke-ZTAssessment`'s collection (gated on
    `$connection.ExchangeOnlineConnected`) and assessment phases.

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
