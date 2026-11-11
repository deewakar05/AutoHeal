FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --gid 10001 autoheal \
    && useradd --uid 10001 --gid 10001 --create-home --shell /sbin/nologin autoheal \
    && mkdir -p /data \
    && chown -R autoheal:autoheal /app /data

COPY monitoring/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY monitoring/src /app/src

USER autoheal

HEALTHCHECK --interval=15s --timeout=3s --retries=3 --start-period=10s \
    CMD python -c "import os, time, sys; p=os.getenv('HEARTBEAT_PATH','/tmp/monitor.heartbeat'); max_age=float(os.getenv('MONITOR_INTERVAL','5'))*3+10; sys.exit(0 if os.path.exists(p) and (time.time()-os.path.getmtime(p))<max_age else 1)"

CMD ["python", "-m", "src.main"]

