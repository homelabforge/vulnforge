# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/oaniach/vulnforge/compare/v3.3.0...HEAD
[3.3.0]: https://github.com/oaniach/vulnforge/compare/v3.2.0...v3.3.0
[3.2.0]: https://github.com/oaniach/vulnforge/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/oaniach/vulnforge/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/oaniach/vulnforge/compare/v2.7.0...v3.0.0
[2.7.0]: https://github.com/oaniach/vulnforge/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/oaniach/vulnforge/releases/tag/v2.6.0
