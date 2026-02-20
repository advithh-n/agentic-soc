FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY . .

RUN useradd -m -r soc && chown -R soc:soc /app
USER soc

EXPOSE 8100

CMD ["python", "server.py"]
