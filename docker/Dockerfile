FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    VENV_ROOT=/opt/venvs

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates build-essential \
    && rm -rf /var/lib/apt/lists/*

# --- app dependencies ---------------------------------------------------
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

# --- external tools, each in its own venv --------------------------------
# holehe, maigret and ghunt pin mutually incompatible versions of aiohttp and
# httpx. Isolating them is the only reliable way to have all three.
RUN set -eux; \
    for tool in holehe maigret ghunt; do \
        python -m venv "$VENV_ROOT/$tool"; \
        "$VENV_ROOT/$tool/bin/pip" install --no-cache-dir --upgrade pip; \
        "$VENV_ROOT/$tool/bin/pip" install --no-cache-dir "$tool" \
            || echo "WARNING: $tool failed to install, its module will report not_configured"; \
    done

# sherlock is a fallback for maigret
RUN python -m venv "$VENV_ROOT/sherlock" \
    && "$VENV_ROOT/sherlock/bin/pip" install --no-cache-dir sherlock-project \
    || echo "WARNING: sherlock unavailable"

COPY app ./app
RUN mkdir -p /app/data

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -fsS http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
