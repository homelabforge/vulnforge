# VulnForge

**Container security insights for your homelab**

VulnForge is a self-hosted dashboard that keeps homelab operators on top of container security. It combines Trivy, Docker Bench, Dockle, and Dive to surface vulnerabilities, configuration drift, and image hygiene issues in one place—all without relying on external SaaS services.

## Features

- **Vulnerability Scanning** - Trivy scanning with KEV tagging, CVSS scoring, and comprehensive history
- **Compliance Monitoring** - Docker Bench CIS compliance checks with weekly reporting
- **Image Linting** - Dockle best practices validation
- **Layer Analysis** - Dive integration for image efficiency insights
- **Secret Detection** - Scan for exposed credentials with false-positive triage
- **Real-time Progress** - SSE-powered scan status updates
- **Smart Notifications** - ntfy integration with configurable alerting
- **Activity Logging** - Complete audit trail of all operations
- **Data Persistence** - SQLite WAL mode with backup/restore

## Quick Start

### Prerequisites

- Docker with Docker Compose
- Access to Docker socket (via socket proxy)
- 1GB RAM minimum
- Linux/macOS/Windows with WSL2

### Installation

1. **Clone or download VulnForge**
   ```bash
   cd /srv/raid0/docker/build/vulnforge
   ```

2. **Configure environment** (optional)

   Create a `.env` file if you need custom settings:
   ```bash
   # Database
   DATABASE_URL=sqlite+aiosqlite:////data/vulnforge.db

   # Docker
   DOCKER_SOCKET_PROXY=tcp://socket-proxy-ro:2375
   TRIVY_CONTAINER_NAME=trivy

   # Scanning
   SCAN_SCHEDULE=0 2 * * *  # Daily at 2 AM
   SCAN_TIMEOUT=300  # 5 minutes per container
   PARALLEL_SCANS=3

   # Notifications
   NTFY_URL=https://ntfy:443
   NTFY_TOPIC=vulnforge
   NTFY_ENABLED=true
   ```

3. **Start VulnForge**
   ```bash
   docker compose up -d
   ```

4. **Access the dashboard**

   Open your browser to `http://localhost:8787` (or your configured host)

### Docker Compose Configuration

VulnForge requires a Docker socket proxy for security. Example `docker-compose.yml`:

```yaml
version: "3.8"

services:
  socket-proxy:
    image: tecnativa/docker-socket-proxy:latest
    container_name: socket-proxy-ro
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      CONTAINERS: 1
      IMAGES: 1
      INFO: 1
      NETWORKS: 1
      VOLUMES: 1
    networks:
      - vulnforge
    restart: unless-stopped

  trivy:
    image: aquasec/trivy:latest
    container_name: trivy
    command: server --listen 0.0.0.0:8080
    volumes:
      - trivy-cache:/root/.cache
    networks:
      - vulnforge
    restart: unless-stopped

  vulnforge:
    image: ghcr.io/oaniach/vulnforge:latest
    container_name: vulnforge
    ports:
      - "8787:8787"
    volumes:
      - vulnforge-data:/data
    environment:
      DOCKER_SOCKET_PROXY: tcp://socket-proxy-ro:2375
      TRIVY_CONTAINER_NAME: trivy
    networks:
      - vulnforge
    depends_on:
      - socket-proxy
      - trivy
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true

volumes:
  trivy-cache:
  vulnforge-data:

networks:
  vulnforge:
    name: vulnforge
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8787` | HTTP port for web interface |
| `DATABASE_URL` | `sqlite+aiosqlite:////data/vulnforge.db` | SQLite database path |
| `DOCKER_SOCKET_PROXY` | `tcp://socket-proxy-ro:2375` | Docker socket proxy URL |
| `TRIVY_CONTAINER_NAME` | `trivy` | Trivy container name |
| `TRIVY_SERVER` | `None` | Optional: Trivy server URL for client mode (e.g., `http://trivy:8080`) - eliminates DB locking issues |
| `SCAN_SCHEDULE` | `0 2 * * *` | Cron schedule for automatic scans |
| `SCAN_TIMEOUT` | `300` | Scan timeout in seconds |
| `PARALLEL_SCANS` | `3` | Number of concurrent container scans |
| `NTFY_ENABLED` | `true` | Enable ntfy notifications |
| `NTFY_URL` | `https://ntfy:443` | ntfy server URL |
| `NTFY_TOPIC` | `vulnforge` | ntfy topic for notifications |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

### Runtime Settings

Additional settings can be configured via the Settings page in the UI:

- Scan scheduling (cron expression)
- Notification thresholds (critical/high CVE counts)
- Secret scanning toggle
- Data retention policies
- Scanner database update preferences

## Usage

### Initial Scan

1. Navigate to the Containers page
2. Click "Scan All" to perform initial vulnerability assessment
3. Monitor real-time progress in the Scans page
4. Review findings in the Vulnerabilities page

### Scheduled Scans

VulnForge automatically scans containers according to the configured schedule (default: daily at 2 AM). Scans run in the background and send notifications for critical findings.

### Managing Vulnerabilities

1. **Review** - Browse vulnerabilities by container, severity, or package
2. **Triage** - Mark vulnerabilities as `accepted`, `false_positive`, or `ignored`
3. **Remediate** - View grouped remediation suggestions by package upgrade
4. **Track KEVs** - Monitor CISA Known Exploited Vulnerabilities

### False Positive Patterns

Create regex patterns to automatically mark recurring false positives:

1. Navigate to Settings → False Positive Patterns
2. Add pattern (e.g., `CVE-2024-.*` for package `libfoo`)
3. Future scans automatically apply patterns

## Development

### Building from Source

```bash
# Install backend dependencies
cd backend
pip install -r requirements.txt

# Install frontend dependencies
cd ../frontend
npm install

# Build frontend
npm run build

# Run backend
cd ../backend
uvicorn app.main:app --reload --port 8787
```

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Frontend linting
cd frontend
npm run lint
```

## Architecture

- **Backend**: Python 3.14 + FastAPI + SQLAlchemy + aiosqlite
- **Frontend**: React 19 + TypeScript + Vite + TailwindCSS
- **Database**: SQLite with WAL mode
- **Scanners**: Trivy (vulnerabilities), Docker Bench (compliance), Dockle (linting), Dive (layers)
- **Deployment**: Docker multi-stage build → GHCR

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

## Version

Current version: **2.7.0**

## License

MIT License - see LICENSE file for details

## Credits

Built with AI collaborators:
- **Claude 4.5 Sonnet** - Original architecture and UI design
- **Codex (GPT-5)** - Ongoing feature development and refactoring
- **Jamey (oaniach)** - Maintainer, product direction, QA, deployment

## Support

- **Issues**: https://github.com/oaniach/vulnforge/issues
- **Discussions**: https://github.com/oaniach/vulnforge/discussions
- **Deployment**: vulnforge.starett.net
