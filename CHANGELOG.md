# Changelog for Get-EntraZTAssess

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

### Changed

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
