FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

ENV PORT=8000
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:${PORT}/.well-known/jwks.json >/dev/null || exit 1

CMD ["gunicorn", "-b", "0.0.0.0:8000", "--workers", "2", "--threads", "4", "--timeout", "60", "main:app"]
