# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Decompose scan pipeline `_process_scan` into 4 discrete stages with documented commit boundaries
- Split monolithic `api.ts` (1140 lines) into modular type and API client files (21 modules)
- Migrate direct API calls to React Query hooks in About, ContainerDetail, ApiKeysCard, DatabaseBackupSection
- Add TTL cache, typed batch getters, and declarative validation to SettingsManager
- Add provider caching, circuit breaker, and exponential backoff to notification dispatcher
- Document repository transaction convention (flush vs commit) across all repositories

### Removed
- Dead header-based auth system (19 settings keys, routes/auth.py, frontend schemas)
- Legacy ntfy-only notifier (`notifier.py`) — replaced by multi-service dispatcher
- Legacy notification settings (`notify_on_scan_complete`, `notify_on_critical`, thresholds)
- Dead frontend code: `authApi`, `userAuth:401` listener, auth Zod validators

### Fixed
- Missing `theme` entry in `DEFAULT_CATEGORIES` (was falling back to 'general' instead of 'ui')
- Deprecated `send_to_ntfy` field in notification rule schemas (API contract preserved)
- Marked `ScanResultRepository` as deprecated (test-only, no production consumers)

### Added
- Frontend test infrastructure: `test-utils.tsx`, `test-factories.ts`
- Tests for SettingsContext, useVulnForge hooks, Dashboard page (110 -> 134 tests)

### Dev Dependencies
- **@typescript-eslint/eslint-plugin**: 8.56.1 → 8.57.0
- **@typescript-eslint/parser**: 8.56.1 → 8.57.0
- **@vitejs/plugin-react-swc**: 4.2.3 → 4.3.0
- **@vitest/coverage-v8**: 4.0.18 → 4.1.0
- **@vitest/ui**: 4.0.18 → 4.1.0
- **ruff**: 0.15.5 → 0.15.6
- **typescript-eslint**: 8.56.1 → 8.57.0
- **vite**: 7.3.1 → 8.0.0
- **vitest**: 4.0.18 → 4.1.0

### App Dependencies
- **pyjwt**: 2.11.0 → 2.12.1

## [4.4.0] - 2026-03-09

### Dev Dependencies
- **eslint**: 10.0.2 → 10.0.3
- **globals**: 17.3.0 → 17.4.0
- **postcss**: 8.5.6 → 8.5.8
- **ruff**: 0.15.4 → 0.15.5

### App Dependencies
- **authlib**: 1.6.8 → 1.6.9
- **fastapi**: 0.133.1 → 0.135.1
- **lucide-react**: 0.575.0 → 0.577.0
- **python-dotenv**: 1.2.1 → 1.2.2
- **recharts**: 3.7.0 → 3.8.0
- **sqlalchemy**: 2.0.47 → 2.0.48

### Changed
- Secrets page redesigned: compact two-column card layout, container name shown on each secret, summary stat cards removed
- Select All moved from bottom of page into the filter bar
- Status filters (Active, False Positives, Accepted Risks, All) now server-side instead of client-side

### Fixed
- Navigation bar overflowing on mobile/tablet; desktop nav now uses icons-only below 1280px with bottom nav only on phones (<768px)
- Batch scan counter accumulating across consecutive scan-all runs instead of resetting
- Trivy scanning now uses client/server mode for faster scans
- Secret counts accumulating across scans instead of showing only latest completed scan per container
- Status filter for False Positives and Accepted Risks returning empty results (backend was excluding them)
- Active secrets filter now correctly excludes both false positives and accepted risks

## [4.3.0] - 2026-02-26

### Dev Dependencies
- **@tailwindcss/vite**: 4.1.18 → 4.2.1
- **@typescript-eslint/eslint-plugin**: 8.55.0 → 8.56.1
- **@typescript-eslint/parser**: 8.55.0 → 8.56.1
- **autoprefixer**: 10.4.24 → 10.4.27
- **eslint**: 10.0.0 → 10.0.2
- **eslint-plugin-react-refresh**: 0.5.0 → 0.5.2
- **jsdom**: 28.0.0 → 28.1.0
- **ruff**: 0.15.1 → 0.15.4
- **tailwindcss**: 4.1.18 → 4.2.1
- **typescript-eslint**: 8.55.0 → 8.56.1

### App Dependencies
- **fastapi**: 0.129.0 → 0.133.1
- **lucide-react**: 0.564.0 → 0.575.0
- **pydantic-settings**: 2.12.0 → 2.13.1
- **react-router-dom**: 7.13.0 → 7.13.1
- **sqlalchemy**: 2.0.46 → 2.0.47
- **tailwind-merge**: 3.4.0 → 3.5.0

### Dockerfile Dependencies
- **oven/bun**: 1.3.9-alpine → 1.3.10-alpine

### HTTP Servers
- **granian**: 2.7.1 → 2.7.2

### Security
- Redact raw Trivy output in error logs (Match/Content JSON keys, 7 logging sites)
- Defensive redaction at API/export boundaries for secret match values
- Redact sensitive ENV/ARG assignments in misconfig code snippets

### Changed
- Redesigned About page: hero, Why VulnForge section, Learn More links, refreshed Built with AI attribution

### Fixed
- Notification event toggles were non-interactive (clicks on the visible track had no effect due to missing input overlay)
- Advanced retry settings (attempts, delay) were never saved — missing state and auto-save payload entries
- False positive key too broad — added `start_line` for precise matching (NULL = wildcard for legacy)
- Secret status accepted arbitrary strings — now validated against enum
- Audit log hardcoded `old_status="active"` — now captures actual prior status
- Severity sort was lexicographic — now uses CRITICAL > HIGH > MEDIUM > LOW ordering
- Bulk status update did N queries — replaced with single `WHERE id IN (...)` query

### Added
- FP pattern deletion unsuppresses affected secrets (with overlap guard)
- Audit logging for FP pattern deletion with unsuppress count
- Migration 009: FP table rebuild for `start_line` column + invalid status cleanup

## [4.2.1] - 2026-02-14

### Dev Dependencies
- **@eslint/js**: 9.39.2 → 10.0.1
- **@types/react**: 19.2.10 → 19.2.14
- **@typescript-eslint/eslint-plugin**: 8.54.0 → 8.55.0
- **@typescript-eslint/parser**: 8.54.0 → 8.55.0
- **@vitejs/plugin-react-swc**: 4.2.2 → 4.2.3
- **eslint**: 9.39.2 → 10.0.0
- **jsdom**: 27.4.0 → 28.0.0
- **ruff**: 0.15.0 → 0.15.1
- **typescript-eslint**: 8.54.0 → 8.55.0

### App Dependencies
- **@tanstack/react-query**: 5.90.20 → 5.90.21
- **authlib**: 1.6.6 → 1.6.8
- **fastapi**: 0.128.2 → 0.129.0
- **lucide-react**: 0.563.0 → 0.564.0

### Dockerfile Dependencies
- **oven/bun**: 1.3.8-alpine → 1.3.9-alpine

### HTTP Servers
- **granian**: 2.7.0 → 2.7.1

### Added
- **ScanOrchestrator Service** — Extracts the two-phase commit pattern (create ScanJob → commit → enqueue) into a reusable service used by both the API and scheduler
- **GET /api/v1/containers/by-image** — Image-based container lookup with registry-agnostic matching for TideWatch integration
- **GET /api/v1/containers/by-name/{name}** — O(1) container lookup by name
- **GET /api/v1/scans/jobs/{job_id}** — Poll scan job status and retrieve linked scan_id on completion
- **Scan Correlation Tracking** — New `scan_jobs` table links API-triggered scan requests to completed scans via job IDs
- **`scan_id` filter on GET /api/v1/scans/cve-delta** — Deterministic CVE delta retrieval instead of relying on time windows
- **ScanJob Retention Cleanup** — Automatically deletes completed/failed jobs older than 30 days and marks orphaned queued jobs as failed
- **37 new tests** covering scan orchestrator, container by-image endpoints, and regression scenarios

### Changed
- **Scheduler uses ScanOrchestrator** — All scheduled scans now go through the priority queue with ScanJob tracking, CVE delta, and batch notifications
- **Additive batch registration** — Overlapping scheduler + API batches no longer destroy each other's notification counters
- **POST /api/v1/scans/scan** — Now returns `job_ids` array; refactored to use ScanOrchestrator
- **Queue worker links ScanJob to Scan** — Includes retry with backoff for WAL checkpoint delay edge cases

### Fixed
- **`scan_id` + `since_hours` filter collision** — Time window is now skipped when `scan_id` is provided
- **Orphan ScanJob rows** — Failed enqueue operations now immediately mark the job as failed

### Deprecated
- **`perform_scan()`** — Legacy scan function; no callers remain after scheduler refactor

### Removed
- **`run_scans_sequentially()` dead code** from scans.py

## [4.2.0] - 2026-02-08

### Added
- **System Info Endpoint** — `/api/v1/system/info` returns app name and version dynamically
- **Frontend Unit Tests** — 110 new tests covering API client, utilities, error handling, and shared components
- **Backend Tests** — 122 new tests covering API keys, scan queue, OIDC, dispatcher, scanner health, and Docker Bench
- **Playwright E2E Tests** — 17 end-to-end tests covering auth, dashboard, navigation, settings, containers, and compliance
- **CI Quality Gates** — Comprehensive pipeline with ruff lint/format, pyright type checking, pytest + Codecov, frontend coverage, and E2E with Playwright artifacts
- **Shared Components** — Toggle switch, TestConnectionButton, and ContainerCard extracted as reusable components
- **Typed Notification Settings** — Replaced `Record<string, unknown>` with proper `NotificationSettings` interface across all notification components
- **API Client Namespaces** — Consolidated all `fetch()` calls into typed `api.ts` with compliance, image compliance, maintenance, and secrets namespaces
- **Auto-Save Hook** — Debounced auto-save with initialization guard and payload diffing

### Changed
- **Settings Page Decomposed** — Extracted into 5 tab components (System, Scanning, Notifications, Security, Data), each with scoped state and auto-save
- **Compliance Page Decomposed** — Extracted into 7 sub-components (ScanProgress, ScoreCard, CategoryBreakdown, TrendChart, FindingsFilters, FindingsTable, IgnoreModal)
- **Containers Page** — Extracted ContainerCard component for cleaner rendering
- **scan_queue._process_scan() Decomposed** — Extracted vulnerability storage, secret detection, Dive analysis, and logging into focused helper methods
- **Version Sourcing** — Switched from `tomllib` to `importlib.metadata.version()` to fix crash in Docker/installed environments
- **Migration 006 Fixed** — Replaced synchronous `create_engine` with async `upgrade(connection)` pattern
- **Pyright Clean** — Resolved all 193 errors at `standard` mode (0 remaining)
- **Image Compliance Summary API** — Fixed field names to match frontend interface expectations
- **Dependency floors bumped** — Updated fastapi, granian, sqlalchemy, httpx, apscheduler, and other backend dependencies to latest stable versions
- **Bun** — Updated to 1.3.8-alpine in both Dockerfile and CI

### Fixed
- **Image Security Dashboard** — Critical and Failures tiles were showing empty due to mismatched field names between backend and frontend
- **VulnerabilityCharts** — Wrong field names for compliance data (pre-existing bug)
- **Duplicate formatRelativeTime** — Consolidated to shared utility
- **Dead computation in scan_queue** — Removed unused fixable_count aggregation
- **ESLint/Vite conflicts** — Fixed coverage directory and cache permission issues

### Removed
- Dead legacy migration code from database.py (~150 lines)
- Duplicate vulnerability building logic in containers.py (extracted to shared helpers)
- Inline toggle CSS replaced by Toggle component
- Redundant Loader2 imports replaced by TestConnectionButton

### Security
- **CodeQL Remediation** — Resolved 48 CodeQL security alerts (16 false positives dismissed with justification)
  - Log injection prevention across backend logging calls
  - Path injection hardening for directory-listing lookup
  - Stack trace exposure fixes (generic messages to users, details in logs only)
  - SSRF validation strengthening
  - Clear-text logging remediation

## [4.1.0] - 2025-01-27

### Added
- **Native Compliance Checker** — Replaced Docker Bench with a Python-based compliance checker that runs directly via Docker API
  - 20 homelab-relevant checks across 4 categories: Daemon Configuration, Container Runtime, Image Security, Host Configuration
  - Built-in remediation guidance with copy-paste snippets
  - Per-container findings with actual/expected values
  - ~0.4 second scan time (vs Docker Bench container overhead)
- **Grouped Compliance Findings View** — Aggregates findings by check ID with expandable rows showing per-container results, reducing 400+ rows to ~20 grouped checks

### Changed
- **Compliance Page** — Updated to use native checker with grouped view; tab renamed from "Docker Bench" to "VulnForge Checker"
- **Dependencies** — Bumped oven/bun, react, react-dom, typescript-eslint, and globals to latest versions

### Removed
- **Docker Bench dependency** — No longer requires `docker-bench-security` container; native checker provides equivalent functionality with better performance

## [4.0.1] - 2025-12-25

### Changed
- **Single-User Model Clarification** — Removed vestigial multi-user RBAC references (unused `groups` field, related settings, and documentation). No functional changes.

## [4.0.0] - 2025-12-22

### Added
- **User Authentication System** — Single-user model with admin account
  - Local authentication (username/password with Argon2id hashing)
  - OIDC/SSO authentication (Authentik integration via OAuth2 authorization code flow)
  - JWT session management (httpOnly cookies, 24-hour expiry)
  - Auto-migration system, protected routes, setup page, login page, profile management
  - Security features: CSRF protection, SSRF prevention, nonce validation
- **Backend Test Coverage** — 116 new tests across image compliance, notifications, Trivy misconfiguration, Docker client, KEV service, and notifier modules (489 → 605 total)

### Changed
- **API Authentication Simplified** — Replaced complex multi-provider system (Authentik ForwardAuth, Custom Headers, Basic Auth) with database-backed API keys using `vf_` prefix and SHA256 hashing
- **Authentication Architecture** — Separated user auth (JWT cookies for browsers) from API auth (ForwardAuth + API keys for integrations)
- **Settings UI** — Refactored to TideWatch-style user profile with action button grid and self-contained modals
- **Settings Security Tab** — Replaced 4-provider auth card with clean API Keys manager (generate/list/revoke)
- **Test Infrastructure** — Fixed fixtures, migrated to Pydantic V2 ConfigDict, updated datetime calls for Python 3.13+

### Fixed
- **Critical SQL Query Bug** — Fixed ignored findings filter in Image Compliance API that was filtering out all non-ignored findings
- **Settings Auto-Save Race Condition** — Fixed spurious save on initial page load due to initialization timing
- **SPA Routing** — Fixed catch-all route intercepting API endpoints
- **Test Warnings** — Eliminated all 56 test suite warnings (Pydantic V2, datetime deprecation, unawaited coroutines)

### Security
- **Password Security** — Argon2id hashing (time_cost=2, memory_cost=102400, parallelism=8)
- **JWT Security** — HS256 with 256-bit secret, httpOnly + SameSite=Lax cookies
- **CSRF/SSRF/Nonce Protection** — State tokens with 10-minute TTL, private IP blocking, ID token replay prevention
- **CodeQL Improvements** — 53% reduction in security warnings (119 → 56) with log injection prevention, path traversal protection, and stack trace exposure fixes

## [3.3.0] - 2025-11-28

### Added
- **Multi-Service Notification System** — Expanded from ntfy-only to 7 services: ntfy, Gotify, Pushover, Slack, Discord, Telegram, and Email (SMTP)
- **Notification Dispatcher** — Centralized event routing with priority-based retry logic and service-specific delay multipliers
- **Frontend Notification UI** — Per-service configuration forms with test buttons and event notification toggles organized by category

### Changed
- **Notification Architecture** — Migrated from single NtfyService to NotificationDispatcher with backward-compatible settings migration

## [3.2.0] - 2025-11-26

### Added
- **Frontend Error Handling** — New `errorHandler.ts` utilities, typed `ApiError` class, and enhanced ErrorBoundary with dev/prod mode, copy-to-clipboard error reports, and retryable indicators
- **Zod Validation Schemas** — Reusable validators for settings with safe integer parsing

### Changed
- **Error Handling Standardization** — Replaced generic `except Exception` handlers with specific exception types across all API endpoints; structured error responses with `detail`, `suggestions`, and `is_retryable` fields

### Fixed
- **Safe Integer Parsing in Settings** — Replaced 12 unsafe `parseInt()` calls with `parseSettingInt()` to prevent NaN values in numeric settings fields

## [3.1.0] - 2025-11-26

### Added
- **Light/Dark Theme Support** — Theme context with dual persistence (localStorage + backend API), FOUC prevention, and Tailwind v4 CSS custom properties
- **CVE Delta Tracking** — New `cves_fixed` and `cves_introduced` columns with automatic delta calculation and `GET /api/v1/scans/cve-delta` endpoint for TideWatch integration

### Changed
- **Larger Header & Navigation** — Improved visual hierarchy with larger title, nav tabs, and shield icon
- **Standardized Button Colors** — All primary buttons now use consistent blue theme
- **Docker Connection** — Simplified to use `DOCKER_HOST` environment variable; removed Docker Connection card from Settings

### Fixed
- **Light Mode Visibility** — Fixed hardcoded `text-white` throughout UI with proper theme-aware colors

### Removed
- Docker Socket Proxy setting from Settings Manager defaults

## [3.0.0] - 2025-11-15

### Changed
- **Granian ASGI Server** — Migrated from uvicorn to Granian for ~15-20% memory reduction and better async handling
- **Tailwind CSS v4** — Migrated from v3 with CSS-based `@theme` directive replacing JavaScript config
- **Python 3.14** — Updated to latest Python release
- **React 19.2** — Updated to latest React with concurrent features
- **Backend/Frontend Dependencies** — Bumped all dependencies to latest stable versions

### Performance
- **79% reduction in initial bundle size** (885 KB → 187 KB) through route-based code splitting, vendor chunking, and memoization
- **70% reduction in network requests** via React Query staleTime configuration
- **60% faster Time to Interactive** (2.5s → <1s)
- Sub-5ms health check response times with 159 MiB average memory footprint

## [2.7.0] - 2025-11-12

### Added
- **CHANGELOG.md** — Version history tracking in Keep a Changelog format
- **README.md** — Project documentation with quick start guide

### Changed
- **Trivy-Only Scanning** — Simplified vulnerability scanning by removing redundant Grype scanner; faster scan times and cleaner codebase

### Removed
- **Grype vulnerability scanner** — Provided 100% overlapping functionality with Trivy; all related services, endpoints, UI components, and consensus logic removed

### Fixed
- **Frontend build script** — Removed `tsc &&` prefix that was blocking CI/CD builds

## [2.6.0] - 2025-11-XX

Initial tracked release with dual-scanner (Trivy + Grype) support, Docker Bench compliance, Dockle linting, Dive analysis, real-time SSE progress, false positive management, CISA KEV integration, ntfy notifications, activity logging, SQLite WAL persistence, secret scanning, and responsive dashboard.

[Unreleased]: https://github.com/homelabforge/vulnforge/compare/v4.4.0...HEAD
[4.4.0]: https://github.com/homelabforge/vulnforge/compare/v4.3.0...v4.4.0
[4.3.0]: https://github.com/homelabforge/vulnforge/compare/v4.2.1...v4.3.0
[4.2.1]: https://github.com/homelabforge/vulnforge/compare/v4.2.0...v4.2.1
[4.2.0]: https://github.com/homelabforge/vulnforge/compare/v4.1.0...v4.2.0
[4.1.0]: https://github.com/homelabforge/vulnforge/compare/v4.0.1...v4.1.0
[4.0.1]: https://github.com/homelabforge/vulnforge/compare/v4.0.0...v4.0.1
[4.0.0]: https://github.com/homelabforge/vulnforge/compare/v3.3.0...v4.0.0
[3.3.0]: https://github.com/homelabforge/vulnforge/compare/v3.2.0...v3.3.0
[3.2.0]: https://github.com/homelabforge/vulnforge/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/homelabforge/vulnforge/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/homelabforge/vulnforge/compare/v2.7.0...v3.0.0
[2.7.0]: https://github.com/homelabforge/vulnforge/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/homelabforge/vulnforge/releases/tag/v2.6.0
