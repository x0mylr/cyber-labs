# Threat Intelligence Pipeline — Dockerfile
# Targets linux/arm64 (Raspberry Pi 4) and linux/amd64
FROM python:3.11-slim

LABEL maintainer="your-security-team@example.com"
LABEL description="Agentic threat intelligence aggregation pipeline"

# Avoid interactive prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install only essential system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY pipeline/ ./pipeline/
COPY main.py .

# Config is volume-mounted; this is the default location
COPY config/ ./config/

# Create data directory
RUN mkdir -p /app/data /app/logs

# Non-root user for security
RUN useradd -r -u 1001 -g root tipl && chown -R tipl:root /app
USER tipl

EXPOSE 8000

# Health check via the /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default: run the API server with background scheduler
CMD ["python", "main.py", "serve"]
