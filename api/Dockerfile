FROM python:3.11-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps (cached layer)
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Application code
COPY . .

# Non-root user
RUN useradd -m -r soc && chown -R soc:soc /app
USER soc

EXPOSE 8050

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8050", "--reload"]
