# BreachReplay API (FastAPI). Build context: repository root.
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --gid 10001 breachreplay \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin breachreplay \
 && mkdir -p /app/backend /workspaces \
 && chown 10001:10001 /workspaces && chmod 0770 /workspaces

WORKDIR /app/backend
COPY backend/requirements.txt ./requirements.txt
# Optional extra CA (corporate TLS-inspecting proxies). Not needed on a normal network.
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export PIP_CERT=/run/secrets/extra_ca; fi; \
    pip install --no-compile -r requirements.txt

COPY backend/app ./app
COPY scripts/generate_demo_pcap.py /app/scripts/generate_demo_pcap.py
COPY demo/rules /app/demo/rules
COPY demo/asset-context.json /app/demo/asset-context.json
COPY showcase /app/showcase
# The synthetic demo capture is generated (deterministically) at build time.
RUN python /app/scripts/generate_demo_pcap.py -o /app/demo/generated/breachreplay-demo.pcap \
 && chmod -R a-w /app

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=4s --start-period=15s --retries=5 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
