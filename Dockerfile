# Multi-stage build for PrivaseeAI.Security
# Stage 1: Builder - Install dependencies
FROM python:3.11-slim as builder

# Set metadata labels
LABEL maintainer="AurelianWare"
LABEL description="PrivaseeAI Security - Privacy-preserving iOS threat detection and monitoring system"
LABEL version="0.1.0"

# Set build arguments
ARG DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy only requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime - Create minimal production image
FROM python:3.11-slim

# Set metadata labels
LABEL maintainer="AurelianWare"
LABEL description="PrivaseeAI Security - Privacy-preserving iOS threat detection and monitoring system"
LABEL version="0.1.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r privasee && \
    useradd -r -g privasee -u 1000 -m -s /bin/bash privasee

# Set working directory
WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application source code
COPY --chown=privasee:privasee src/privaseeai_security /app/privaseeai_security
COPY --chown=privasee:privasee pyproject.toml /app/
COPY --chown=privasee:privasee scripts/healthcheck.py /app/scripts/healthcheck.py

# Create necessary directories
RUN mkdir -p /app/logs /app/data && \
    chown -R privasee:privasee /app

# Switch to non-root user
USER privasee

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python /app/scripts/healthcheck.py || exit 1

# Expose port (placeholder for future API)
EXPOSE 8000

# Set entrypoint
ENTRYPOINT ["python", "-m"]
CMD ["privaseeai_security"]
