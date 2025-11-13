# Multi-stage Dockerfile for VulnForge

# Stage 1: Build frontend
FROM node:24-alpine AS frontend-builder

WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# Stage 2: Build backend
FROM python:3.14-slim AS backend-builder

WORKDIR /app

# Upgrade pip to latest version
RUN pip install --no-cache-dir --upgrade pip

# Copy requirements and install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend ./

# Stage 3: Production image
FROM python:3.14-slim

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

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8787"]
