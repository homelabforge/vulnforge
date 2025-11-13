# VulnForge Backend Test Suite

## Overview

Comprehensive test suite for VulnForge authentication, authorization, and security features.

## Test Coverage

### Authentication Tests (`test_authentication.py`)
- **Authentik Provider**: Forward auth header validation, admin detection, group parsing
- **API Key Provider**: Constant-time comparison, authorization checks
- **Basic Auth Provider**: bcrypt password verification, DoS protection
- **Custom Headers Provider**: Reverse proxy header authentication
- **Header Verification**: Shared secret and trusted proxy IP validation
- **Input Validation**: Username/email length limits, control character rejection

### Settings Authorization Tests (`test_settings_authorization.py`)
- **Admin-Only Access**: All settings endpoints require admin privileges
- **Privilege Escalation Prevention**: Non-admins cannot disable auth or modify security settings
- **Cache Immutability**: Settings cache returns copies to prevent mutations

### Secret Redaction Tests (`test_secret_redaction.py`)
- **Trivy Scanner Redaction**: Code snippets redacted before database storage
- **Log Redaction**: Common secret patterns (API keys, tokens, passwords) redacted
- **API Response Safety**: Secrets not exposed in API responses
- **Settings Masking**: Sensitive settings values masked when displayed

### Repository Tests (`test_repositories.py`)
- **Container Repository**: CRUD operations, querying by container ID
- **Scan Result Repository**: Scan creation, vulnerability associations, latest scan retrieval
- **Secret Repository**: Secret finding storage with redacted code snippets

### Path Normalization Tests (`test_path_normalization.py`)
- **Traversal Protection**: Path traversal attempts (../, ./, etc.) blocked
- **Double Slash Normalization**: Multiple slashes normalized correctly
- **URL Encoding**: Encoded path components decoded and normalized
- **Case Insensitivity**: Mixed-case API paths properly detected
- **Edge Cases**: /api without trailing slash, null bytes, backslashes

### Maintenance API Tests (`test_api_maintenance.py`) - **SECURITY CRITICAL**
- **Backup Path Traversal Prevention**: Path traversal blocked in backup filenames
- **Null Byte Injection**: Null byte injection in filenames rejected
- **Admin Authorization**: All maintenance endpoints require admin privileges
- **Cleanup Validation**: Days parameter validation, negative values rejected
- **KEV Refresh**: KEV catalog refresh authorization and success handling
- **Cache Management**: Cache stats and clear operations

### Auth Dependencies Tests (`test_dependencies_auth.py`)
- **require_auth()**: Authenticated user validation, anonymous user rejection
- **require_admin()**: Admin privilege checking, privilege escalation prevention
- **get_current_user()**: User retrieval, optional auth support
- **Dependency Chaining**: Auth checked before admin, user object preservation
- **Missing State Handling**: Graceful handling of missing request.state

### Middleware Edge Cases Tests (`test_middleware_edge_cases.py`) - **SECURITY CRITICAL**
- **Advanced Path Normalization**: Null bytes, backslashes, Unicode variations, overlong UTF-8
- **Mixed Encoding Attacks**: Double encoding, mixed case, Windows path separators
- **Cache Race Conditions**: Concurrent access safety, refresh during access, mutation isolation
- **Provider Factory Errors**: Invalid provider names, corrupted settings handling
- **Anonymous User Handling**: Frontend vs API path differentiation
- **Database Corruption**: Invalid JSON settings, missing settings, defaults fallback
- **Request State Corruption**: Missing user attribute, partial user objects
- **Cache Timing Attacks**: Consistent timing to prevent timing attacks

## Running Tests

### Prerequisites

Install dev dependencies:
```bash
cd /srv/raid0/docker/build/vulnforge/backend
pip install -e '.[dev]'
```

### Run All Tests

```bash
pytest
```

### Run Specific Test Files

```bash
pytest tests/test_authentication.py
pytest tests/test_settings_authorization.py
pytest tests/test_secret_redaction.py
pytest tests/test_repositories.py
pytest tests/test_path_normalization.py
```

### Run with Coverage

```bash
pytest --cov=app --cov-report=html
```

### Run with Verbose Output

```bash
pytest -v
```

## Test Database

Tests use an in-memory SQLite database configured in `conftest.py`. Each test gets a fresh database instance.

## Fixtures

### `db_session`
Async database session for tests

### `db_with_settings`
Database session pre-populated with default settings

### `client`
TestClient for API endpoint testing with dependency overrides

### `mock_settings`
Mock settings dictionary for auth provider testing

## Security Hardening Verified

The test suite verifies:

1. ✅ **Settings Router Authorization** - Admin-only access to all settings endpoints
2. ✅ **Path Normalization** - Comprehensive path traversal prevention
3. ✅ **Async Event Loop** - bcrypt runs in thread pool
4. ✅ **Cache Immutability** - Settings cache returns copies
5. ✅ **Header Verification** - Shared secret and trusted proxy IP checks
6. ✅ **Secret Redaction** - Code snippets redacted before storage
7. ✅ **Input Validation** - Length limits and control character rejection

## CI/CD Integration

To run tests in CI/CD pipelines:

```yaml
- name: Run Backend Tests
  run: |
    cd /srv/raid0/docker/build/vulnforge/backend
    pip install -e '.[dev]'
    pytest --junitxml=test-results.xml
```

### API Container Tests (`test_api_containers.py`)
- **Container Discovery**: Docker integration, error handling, special characters
- **Container Listing**: Pagination, authentication, filtering
- **Activity Logging**: Discovery operations logging
- **Error Handling**: Docker connection, permission denied, timeouts

### API Vulnerabilities Tests (`test_api_vulnerabilities.py`)
- **Filtering**: Severity, status, fixable, KEV filtering
- **SQL Injection Prevention**: Filter parameter sanitization
- **Bulk Operations**: Bulk update, status changes
- **Remediation Groups**: Grouping for efficient remediation
- **Export**: CSV and JSON export functionality
- **Pagination**: Skip/limit parameters, negative value rejection

### API Secrets Tests (`test_api_secrets.py`)
- **Secret Retrieval**: Listing, filtering, container-specific
- **Redaction Verification**: API responses contain redacted code
- **Bulk Operations**: False positive marking, pattern creation
- **Export Security**: CSV export with redaction enforcement
- **Pattern Management**: False positive pattern CRUD

### Trivy Scanner Tests (`test_trivy_scanner.py`)
- **Image Scanning**: Success/failure paths, timeout handling
- **Secret Scanning**: Integration with Trivy secret detection
- **JSON Parsing**: Malformed response handling
- **Database Management**: Freshness checks, offline mode
- **Error Handling**: Docker exec failures, image not found

### Settings Manager Tests (`test_settings_manager.py`)
- **Retrieval**: Get by key, defaults, type conversion
- **Type Safety**: Integer, boolean, JSON parsing
- **Updates**: Set, bulk update, cache invalidation
- **JSON Handling**: List/dict settings, invalid JSON
- **Defaults**: DEFAULTS dict integrity, fallback behavior

### Validators Tests (`test_validators.py`)
- **Cron Expressions**: Valid/invalid patterns, field validation
- **URLs**: Scheme restriction, XSS prevention
- **Severity Levels**: Valid levels, case-insensitive
- **Integer Ranges**: Min/max bounds, negative values
- **Boolean Conversion**: Truthy/falsy variations
- **Topic Names**: Character restrictions, length limits
- **String Sanitization**: Length limits, special characters, Unicode
- **Path Validation**: Traversal prevention, absolute path rejection

### KEV Service Tests (`test_kev_service.py`)
- **Catalog Fetching**: CISA API integration, network errors
- **CVE Lookup**: KEV info retrieval, missing CVEs
- **Freshness**: Cache staleness detection, age checking
- **Offline Mode**: Cached catalog usage, empty catalog handling

### Scheduler Tests (`test_scheduler.py`)
- **Startup/Shutdown**: Graceful start and stop
- **Job Scheduling**: Vulnerability scans, compliance, KEV refresh
- **Cron Parsing**: Expression validation, invalid patterns
- **Schedule Updates**: Runtime schedule changes
- **Timezone Handling**: System timezone usage
- **Error Handling**: Job failures, startup errors

### Notifier Tests (`test_notifier.py`)
- **Notification Sending**: Success, network errors, disabled state
- **Rule Evaluation**: Threshold checking, severity filtering
- **Priority Mapping**: Critical → high priority
- **Retry Logic**: Failure recovery, rate limiting
- **Authentication**: Token-based auth with ntfy
- **Rate Limiting**: 429 response handling

### Scan Workflow Integration Tests (`test_scan_workflow_integration.py`)
- **End-to-End**: Queue → scan → store → notify workflow
- **Scanner Fallback**: Trivy failure → Grype fallback
- **Transaction Safety**: Database rollback on failure
- **Batch Scanning**: Multiple containers, partial failures
- **KEV Integration**: KEV checking during scans
- **False Positives**: Pattern application during scans
- **Notifications**: Post-scan notification delivery
- **Concurrency**: Duplicate prevention, parallel scans

## Test Statistics

- **Test Files**: 19 (complete coverage!)
- **Test Classes**: 50+
- **Test Methods**: 200+
- **Lines of Test Code**: ~5,000+
- **Coverage Areas**:
  - Authentication (4 providers + header verification)
  - Authorization (settings endpoints, admin dependencies)
  - Secret handling (redaction, masking, export)
  - Data repositories (containers, scans, secrets, vulnerabilities)
  - Path security (normalization, traversal, advanced attacks)
  - Maintenance endpoints (backup security, KEV, cache, cleanup)
  - Middleware edge cases (concurrency, corruption, timing attacks)
  - Dependency injection (auth, admin, error handling)
  - API endpoints (containers, vulnerabilities, secrets, scans)
  - Services (Trivy, KEV, scheduler, notifier, settings)
  - Input validation (cron, URLs, severity, paths, strings)
  - Integration workflows (end-to-end scans, batch operations)
