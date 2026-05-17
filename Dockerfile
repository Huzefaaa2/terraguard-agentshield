FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TERRAGUARD_AGENTSHIELD_DATA_DIR=/var/lib/agentshield

WORKDIR /app

RUN groupadd --system --gid 10001 agentshield \
    && useradd --system --uid 10001 --gid agentshield --home-dir /var/lib/agentshield agentshield \
    && mkdir -p /var/lib/agentshield/evidence /tmp/agentshield \
    && chown -R agentshield:agentshield /var/lib/agentshield /tmp/agentshield

COPY pyproject.toml README.md LICENSE MANIFEST.in /app/
COPY src /app/src
COPY policies /app/policies

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir .

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()"

CMD ["terraguard-agentshield", "api", "serve", "--host", "0.0.0.0", "--port", "8000", "--data-dir", "/var/lib/agentshield"]
