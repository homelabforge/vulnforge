# Multi-stage Dockerfile for VulnForge

# Stage 1: Build frontend
FROM oven/bun:1.3.8-alpine AS frontend-builder

WORKDIR /app/frontend

# Install dependencies for native bindings (@swc/core, @tailwindcss/oxide)
# Both gcompat and build-base are required for TailwindCSS v4 in Alpine
# See: https://github.com/tailwindlabs/tailwindcss/issues/6690
RUN apk add --no-cache gcompat build-base

COPY frontend/package.json frontend/bun.lock ./
RUN bun install --frozen-lockfile

COPY frontend/ ./

# Build production bundle
RUN bun run build

# Verify build output exists (fail fast if build failed)
RUN test -d dist && test -f dist/index.html

# Stage 2: Build backend
FROM python:3.14-slim AS backend-builder

WORKDIR /app

# Upgrade pip to latest version and clean up old metadata
RUN pip install --no-cache-dir --upgrade pip && \
    rm -rf /usr/local/lib/python3.14/site-packages/pip-25.2.dist-info 2>/dev/null || true

# Copy backend code and install from pyproject.toml
COPY backend ./
RUN pip install --no-cache-dir .

# Stage 3: Production image
FROM python:3.14-slim

# Build arguments for metadata
ARG BUILD_DATE

# OCI-standard labels
LABEL org.opencontainers.image.authors="HomeLabForge"
LABEL org.opencontainers.image.title="VulnForge"
LABEL org.opencontainers.image.url="https://www.homelabforge.io"
LABEL org.opencontainers.image.description="Container vulnerability scanning and management platform"

# HTTP server metadata
LABEL http.server.name="granian"
LABEL http.server.version="2.7.0"
LABEL http.server.type="asgi"

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Copy Python dependencies from builder
COPY --from=backend-builder /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
COPY --from=backend-builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --from=backend-builder /app/app /app/app
COPY --from=backend-builder /app/pyproject.toml ./

# Copy frontend build
COPY --from=frontend-builder /app/frontend/dist ./static

# Create non-root user for security
RUN useradd --uid 1000 --user-group --system --create-home --no-log-init vulnforge

# Create data directory and set proper permissions
RUN mkdir -p /data && \
    chown -R vulnforge:vulnforge /app /data && \
    chmod -R 755 /app && \
    chmod 755 /data

# Switch to non-root user
USER vulnforge

# Expose port
EXPOSE 8787

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8787/health || exit 1

# Run application with Granian (Rust-based ASGI server)
# Using 1 worker due to stateful background services (APScheduler, scan queue)
# Granian auto-configures threads for optimal performance
CMD ["granian", "--interface", "asgi", "--host", "0.0.0.0", "--port", "8787", "--workers", "1", "app.main:app"]
