# BreachReplay Zeek analyzer worker.
# Runs Zeek offline against captures placed in the shared workspace volume.
# No outbound network: the compose file attaches it to an internal-only network.
ARG ZEEK_IMAGE=zeek/zeek:7.0.5
FROM ${ZEEK_IMAGE}

RUN groupadd --gid 10001 breachreplay \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin breachreplay \
 && mkdir -p /workspaces /opt/breachreplay/app/analyzers /opt/breachreplay/zeek \
 && chown 10001:10001 /workspaces && chmod 0770 /workspaces

COPY backend/app/__init__.py /opt/breachreplay/app/
COPY backend/app/analyzers/__init__.py backend/app/analyzers/process.py backend/app/analyzers/zeek.py \
     backend/app/analyzers/suricata.py backend/app/analyzers/worker.py /opt/breachreplay/app/analyzers/
COPY analyzer/config/zeek/breachreplay.zeek /opt/breachreplay/zeek/

ENV PYTHONPATH=/opt/breachreplay \
    PYTHONDONTWRITEBYTECODE=1 \
    ZEEK_POLICY_PATH=/opt/breachreplay/zeek/breachreplay.zeek \
    WORKSPACE_ROOT=/workspaces

USER 10001:10001
EXPOSE 8700
HEALTHCHECK --interval=10s --timeout=4s --start-period=10s --retries=5 \
  CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8700/health', timeout=3)"]
ENTRYPOINT ["python3", "-m", "app.analyzers.worker", "--tool", "zeek"]
