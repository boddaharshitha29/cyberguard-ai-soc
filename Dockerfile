# Multi-stage lightweight Python Dockerfile for CYBERGUARD AI SOC
FROM python:3.11-slim

WORKDIR /app

# Install minimal OS dependencies for network & builds
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and models
COPY . .

# Expose default Streamlit port
EXPOSE 8501

# Streamlit healthcheck
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Launch Streamlit application in headless production mode
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
