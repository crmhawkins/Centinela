FROM python:3.11-slim

LABEL maintainer="CENTINELA Security Monitor"
LABEL description="Docker container security monitoring system"
LABEL version="1.0.0"

# ---------------------------------------------------------------------------
# System dependencies
# ---------------------------------------------------------------------------
# inotify-tools : inotifywait for filesystem event monitoring
# procps        : ps, top – process inspection inside container /proc
# net-tools     : netstat, ifconfig – network diagnostics
# iputils-ping  : connectivity checks during startup
# curl          : webhook delivery testing / healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    inotify-tools \
    procps \
    net-tools \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------
WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/

# ---------------------------------------------------------------------------
# Runtime directories
# ---------------------------------------------------------------------------
# /app/data   – SQLite database and any other persistent state
# /app/logs   – Centinela's own structured log files
# /app/config – centinela.yml + projects/*.yml (mounted read-only at runtime)
RUN mkdir -p /app/data /app/logs /app/config/projects

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1
ENV CENTINELA_CONFIG=/app/config/centinela.yml
# Prevent Python from writing .pyc files into the image layers
ENV PYTHONDONTWRITEBYTECODE=1

# ---------------------------------------------------------------------------
# Volumes
# ---------------------------------------------------------------------------
# Declare the directories that should be externally managed.
# The host bind-mounts in docker-compose.yml override these.
VOLUME ["/app/data", "/app/logs", "/app/config"]

# ---------------------------------------------------------------------------
# Healthcheck
# ---------------------------------------------------------------------------
# Verifies that the Docker daemon is still reachable from inside the container.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import docker; docker.from_env().ping()" || exit 1

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
CMD ["python", "src/main.py"]
