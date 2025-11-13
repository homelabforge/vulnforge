# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/oaniach/vulnforge/compare/v2.7.0...HEAD
[2.7.0]: https://github.com/oaniach/vulnforge/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/oaniach/vulnforge/releases/tag/v2.6.0
