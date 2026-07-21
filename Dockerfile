FROM python:3.12-slim

# scapy needs libpcap at runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first (layer caching: deps rarely change)
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Then copy the application code
COPY netscope/ ./netscope/

EXPOSE 8000

CMD ["uvicorn", "netscope.api:app", "--host", "0.0.0.0", "--port", "8000"]
