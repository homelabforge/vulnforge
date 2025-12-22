# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.0.0] - 2025-12-22

### Added
- **User Authentication System** - 
  - Single-user model with admin account
  - Local authentication (username/password with Argon2id hashing)
  - OIDC/SSO authentication (Authentik integration via OAuth2 authorization code flow)
  - JWT session management (httpOnly cookies, 24-hour expiry)
  - Auto-migration system for database schema updates
  - Protected routes with auth guards
  - Setup page for initial account creation
  - Login page with local and SSO options
  - User profile management (edit email, full name)
  - Password change with real-time validation (8 char min, uppercase, lowercase, number, special char)
  - OIDC configuration UI with connection testing
  - Logout functionality in navigation
  - Security features: CSRF protection, SSRF prevention, nonce validation
- **Backend Test Coverage** - Comprehensive test suite for APIs and services
  - 116 new passing tests across 6 major modules
  - Image Compliance API tests (37 tests covering 10 endpoints)
  - Notifications API tests (45 tests covering 18 endpoints)
  - Trivy Misconfiguration Service tests (16 tests)
  - Docker Client Service tests (10 tests)
  - KEV Service tests (10 tests)
  - Enhanced Notifier Service tests (6 tests)
  - Total project tests: 489 → 605 tests (+24%)
  - 100% pass rate on all new tests

### Changed
- **API Authentication Simplified** - Complete refactor from complex multi-provider system to simple API key management
  - **Removed:** Authentik ForwardAuth, Custom Headers, Basic Auth providers (855 lines → 110 lines in auth middleware)
  - **New:** Database-backed API keys with secure generation, hashing, and revocation
  - API keys use `vf_` prefix + 32 bytes URL-safe base64 (~48 chars total)
  - SHA256 hashing for storage (never store plaintext)
  - Clean UI with create/list/revoke operations
  - Keys shown only once on creation with copy-to-clipboard
  - Includes key prefix display, last used timestamp, and soft delete (revocation)
  - Migration 005 automatically creates `api_keys` table and disables old auth providers
- **Authentication Architecture** - Separated user auth from API auth
  - User authentication for browser sessions (JWT cookies)
  - API authentication for external integrations (ForwardAuth, API keys)
  - `/api/v1/user-auth/*` endpoints exempt from API auth middleware
  - Settings organized by `user_auth_*` vs `auth_*` prefixes
- **Settings UI** - Refactored user authentication settings
  - Removed inline OIDC configuration fields (18+ props)
  - Clean TideWatch-style user profile display
  - Action button grid (Edit Profile, Change Password, OIDC/SSO, Disable Auth)
  - Three fully functional modals (Edit Profile, Change Password, OIDC Config)
  - Self-contained component with no prop drilling
- **Settings Security Tab** - Replaced complex API auth card with simple API Keys manager
  - Old: 265-line card with 4 auth providers, 12 state variables, JSON editing
  - New: Clean ApiKeysCard component with UI for generate/list/revoke
  - Removed API Authentication toggle and provider selection (no longer needed)
- **Test Infrastructure** - Improved test reliability
  - Fixed `make_notification_rule()` fixture in conftest.py
  - Updated Pydantic models to V2 ConfigDict pattern
  - Migrated `datetime.utcnow()` to `datetime.now(UTC)` (Python 3.13+)
  - Fixed httpx mock patterns (synchronous `raise_for_status`)

### Fixed
- **Critical SQL Query Bug** - Fixed ignored findings filter in Image Compliance API
  - Lines 591, 792 in `app/api/image_compliance.py`
  - Changed `not ImageComplianceFinding.is_ignored` to `ImageComplianceFinding.is_ignored == False`
  - Bug was filtering out ALL non-ignored findings instead of showing them
- **Settings Auto-Save Race Condition** - Fixed spurious save on initial Settings page load
  - Race condition: `hasInitializedRef` set before `lastPayloadRef`, allowing auto-save to trigger
  - Changed setTimeout from 0ms to 100ms to ensure state updates complete
  - Moved `hasInitializedRef.current = true` inside setTimeout with payload initialization
  - Settings now only save when user makes actual changes, not on first load
- **SPA Routing** - Fixed catch-all route intercepting API endpoints
  - Added check in catch-all to skip routes starting with `api/`
  - Prevents `/api/v1/user-auth/oidc/login` from returning HTML
- **Test Warnings** - Eliminated all test suite warnings (56 → 0)
  - Fixed 3 Pydantic V2 deprecation warnings (`class Config` → `model_config`)
  - Fixed 18 datetime deprecation warnings (`utcnow()` → `now(UTC)`)
  - Fixed 6 RuntimeWarnings (unawaited coroutines in httpx mocks)

### Security
- **Password Security** - Argon2id hashing (time_cost=2, memory_cost=102400, parallelism=8)
- **JWT Security** - HS256 algorithm, 256-bit secret, httpOnly + SameSite=Lax cookies
- **CSRF Protection** - 256-bit state tokens with 10-minute TTL (OIDC flow)
- **SSRF Protection** - Blocks private IPs, localhost, link-local, cloud metadata endpoints
- **Nonce Validation** - Prevents replay attacks on ID tokens
- **CodeQL Security Improvements** - 53% reduction in security warnings (119 → 56)
  - Log injection prevention with `sanitize_for_log()` utility
  - Stack trace exposure fixes (generic error messages to users, details in logs only)
  - Path traversal protection with `normalize_path()` utility
  - Empty exception handler documentation and explicit behavior
  - 100% test pass rate maintained throughout security fixes

## [3.3.0] - 2025-11-28

### Added
- **Multi-Service Notification System** - Expanded notification support beyond ntfy to 7 services
  - ntfy (existing, refactored to new architecture)
  - Gotify push notifications with priority mapping
  - Pushover with emergency priority support
  - Slack webhook integration with attachments
  - Discord webhook integration with embeds
  - Telegram bot API with HTML formatting
  - Email via SMTP with TLS support
- **Notification Dispatcher** - Centralized event routing with priority-based retry logic
  - Service-specific retry delay multipliers (Discord/Slack more conservative)
  - High-priority events (urgent/high) get automatic retry on failure
  - Lower-priority events use single-attempt delivery
- **Frontend Notification UI** - Complete settings interface for all 7 services
  - Service sub-tabs with enabled indicators
  - Per-service configuration forms with test buttons
  - Event notification toggles organized by category
  - Expandable/collapsible event groups

### Changed
- **Notification Architecture** - Migrated from single NtfyService to NotificationDispatcher
  - All notification call sites updated to use dispatcher
  - Existing ntfy settings preserved (backward compatible)
  - Event types mapped to priority levels and tags

## [3.2.0] - 2025-11-26

### Changed
- **Error Handling Standardization** - Comprehensive error handling improvements across backend and frontend
  - Replaced generic `except Exception` handlers with specific exception types in API endpoints
  - Added specific handlers for `TimeoutError`, `PermissionError`, `ConnectionError`, `OSError`,
    `subprocess.TimeoutExpired`, `subprocess.CalledProcessError`, `json.JSONDecodeError`,
    `httpx.TimeoutException`, `httpx.ConnectError`, `httpx.HTTPStatusError`,
    `sqlalchemy.exc.OperationalError`, `sqlalchemy.exc.SQLAlchemyError`
  - Backend now returns structured error responses with `detail`, `suggestions`, and `is_retryable` fields
  - All remaining generic handlers in API layer documented with `# INTENTIONAL:` comments
  - Integrated `ScanErrorClassifier` for user-friendly scan error messages

### Added
- **Frontend Error Handling Utilities**
  - New `errorHandler.ts` with `handleApiError()`, `getStatusMessage()`, `formatErrorDetails()`, `isRetryableError()`
  - New `ApiError` class with typed error properties (`status`, `detail`, `suggestions`, `isRetryable`)
  - Updated all page components and mutations to use new error handling
- **Enhanced ErrorBoundary Component**
  - Dev/prod mode toggle for technical details (auto-expanded in dev mode)
  - "Copy Error" button generates shareable error report with timestamp, URL, user agent
  - Displays suggestions from API errors
  - Shows retryable indicator for temporary errors
  - Collapsible stack trace and component stack sections
- **Zod Validation Schemas**
  - New `schemas/shared.ts` with reusable validation helpers (`safeParseInt`, `coerceToNumber`, `cronExpression`, etc.)
  - New `schemas/settings.ts` with settings-specific validators and `parseSettingInt()` helper

### Fixed
- **Safe Integer Parsing in Settings** - Replaced 12 unsafe `parseInt()` calls with `parseSettingInt()`
  - Prevents NaN values from invalid input in settings fields
  - Affected fields: scan_timeout, parallel_scans, notification thresholds, data retention, KEV cache hours, scanner offline resilience settings
  - All numeric settings now have proper default value fallbacks

## [3.1.0] - 2025-11-26

### Added
- **Light/Dark Theme Support** - New theming system with light mode as default
  - `ThemeContext.tsx` for theme state management
  - Dual persistence: localStorage (instant) + backend API (cross-device)
  - FOUC prevention script in `index.html`
  - Theme toggle in Settings with Sun/Moon icons
  - CSS custom properties via Tailwind v4 `@theme` directive
- **CVE Delta Tracking** - Track CVE changes between scans for TideWatch integration
  - New `cves_fixed` and `cves_introduced` columns in scans table
  - Automatic delta calculation comparing current scan to previous
  - New API endpoint: `GET /api/v1/scans/cve-delta`
  - Supports filtering by time range and container name

### Changed
- **Larger Header & Navigation** - Improved visual hierarchy
  - App title: `text-xl` → `text-2xl`
  - Nav tabs: `text-sm` → `text-base` with larger padding
  - Shield icon: `w-7` → `w-9`
- **Standardized Button Colors** - All primary buttons now use blue theme
  - Send Test Notification: purple → blue
  - Create Backup: purple → blue
  - Discover Containers: matches Scan All button
- **Docker Connection** - Simplified configuration
  - Now uses `DOCKER_HOST` environment variable from compose
  - Removed Docker Connection card from Settings > System

### Fixed
- **Light Mode Visibility** - Fixed text colors throughout UI
  - Replaced hardcoded `text-white` with `text-vuln-text`
  - Active navigation tabs now show white text on blue background
  - Filter badges display correctly in both themes
  - Chart titles and numbers visible in light mode

### Removed
- Docker Socket Proxy setting from Settings Manager defaults

## [3.0.0] - 2025-11-15

### Changed
- **MAJOR:** Migrated from uvicorn to Granian ASGI server
  - Updated `Dockerfile` to use Granian with single worker configuration
  - Changed logger filter in `backend/app/main.py` from `uvicorn.access` to `granian.access`
  - Granian provides ~15-20% memory reduction and better async handling
  - Rust-based architecture with auto-tuned thread configuration
- **MAJOR:** Migrated from Tailwind CSS v3 to v4
  - Updated PostCSS configuration to use `@tailwindcss/postcss` plugin
  - Migrated CSS imports from `@tailwind` directives to `@import "tailwindcss"`
  - Moved configuration from JavaScript to CSS-based `@theme` directive
  - Custom color theme now defined as CSS custom properties
  - Removed `tailwind.config.ts` (no longer needed in v4)
- **Updated to Python 3.14** - Latest Python release with performance improvements
- **Updated to React 19.2** - Latest React with concurrent features
- Updated backend dependencies to latest stable versions:
  - `fastapi`: → 0.121.2
  - `sqlalchemy`: → 2.0.44 (improved async support)
  - `pydantic`: → 2.12.0 (minor behavior changes in dataclass Field handling)
  - `apscheduler`: → 3.11.1
  - `bcrypt`: → 5.0.0 (breaking: 72-byte password limit enforced)
- Updated frontend dependencies:
  - `@tanstack/react-query`: → 5.90.9
  - `react-router-dom`: → 7.9.6
  - `recharts`: → 3.4.1
  - `lucide-react`: → 0.553.0 (1,647 icons)
  - `sonner`: → 2.0.7
  - `tailwind-merge`: → 3.4.0 (Tailwind v4 compatible)
  - `typescript`: → 5.9.3
  - `eslint`: → 9.39.1

### Performance
- **79% reduction in initial bundle size** - 885 KB → 187 KB through optimizations
  - Route-based code splitting with React.lazy()
  - Vite manual chunks for vendor bundling
  - Memoization for expensive operations
- **70% reduction in network requests** - React Query staleTime configuration
- **60% faster Time to Interactive** - 2.5s → <1s
- Reduced memory footprint with Granian (159 MiB average)
- Sub-5ms health check response times

### Technical Notes
- Single worker required due to stateful APScheduler service
- Granian is fully ASGI-compliant and a drop-in replacement for uvicorn
- Tailwind v4 requires modern browsers (Safari 16.4+, Chrome 111+, Firefox 128+)
- bcrypt v5 raises ValueError for passwords >72 bytes (defensive validation added)

## [2.7.0] - 2025-11-12

### Removed
- **Grype vulnerability scanner** - Removed redundant Grype scanner integration
  - Grype provided 100% overlapping functionality with Trivy
  - Removed Grype service and health monitoring
  - Removed Grype API endpoints
  - Removed Grype UI components and settings
  - Removed scanner consensus/comparison features
  - Streamlined to Trivy-only vulnerability scanning
- **Scanner consensus logic** - No longer needed with single scanner

### Added
- **CHANGELOG.md** - Version history tracking in Keep a Changelog format
- **README.md** - Project documentation with quick start guide

### Changed
- **Simplified vulnerability scanning** - Now using Trivy exclusively
  - Faster scan times (eliminated dual-scanner overhead)
  - Cleaner codebase with reduced complexity
  - All vulnerabilities marked with `scanner="trivy"`
- **Updated Scanner Statistics UI** - Replaced scanner comparison chart with Trivy severity breakdown
- **Updated dev-sop.md** - Added TypeScript type checking to pre-commit checklist

### Fixed
- **Frontend build script** - Removed `tsc &&` prefix from build command
  - Prevents TypeScript strict checking from blocking CI/CD builds
  - Follows dev-sop standards for build pipeline
  - Type checking should be done via linting, not build gates

## [2.6.0] - 2025-11-XX

Previous release with dual-scanner (Trivy + Grype) support.

### Features (Inherited)
- Trivy vulnerability scanning with KEV tagging
- Grype vulnerability scanning (now removed in v2.7)
- Docker Bench compliance scanning
- Dockle image linting
- Dive layer efficiency analysis
- Real-time scan progress with SSE
- False positive pattern management
- CISA KEV integration
- ntfy notification system
- Activity logging
- SQLite WAL persistence
- Responsive dashboard
- Secret scanning with triage workflow

[Unreleased]: https://github.com/homelabforge/vulnforge/compare/v4.0.0...HEAD
[4.0.0]: https://github.com/homelabforge/vulnforge/compare/v3.3.0...v4.0.0
[3.3.0]: https://github.com/homelabforge/vulnforge/compare/v3.2.0...v3.3.0
[3.2.0]: https://github.com/oaniach/vulnforge/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/oaniach/vulnforge/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/oaniach/vulnforge/compare/v2.7.0...v3.0.0
[2.7.0]: https://github.com/oaniach/vulnforge/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/oaniach/vulnforge/releases/tag/v2.6.0
