FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy QERIS codebase and datasets
COPY qeris/ /app/qeris/
COPY data/ /app/data/
COPY conftest.py /app/

# Ensure TLS self-signed certificates exist
RUN python qeris/s2/certs.py

ENV PYTHONPATH=/app
EXPOSE 8000 8001

# Default command: start Gateway Service
CMD ["python", "qeris/s2/gateway.py"]
