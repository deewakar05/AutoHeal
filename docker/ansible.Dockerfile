FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/workspace \
    ANSIBLE_HOME=/tmp/.ansible \
    ANSIBLE_LOCAL_TEMP=/tmp/.ansible/tmp

WORKDIR /workspace

RUN apk add --no-cache docker-cli \
    && addgroup -g 10001 -S autoheal \
    && adduser -u 10001 -S -G autoheal -h /tmp/autoheal-home -s /sbin/nologin autoheal \
    && mkdir -p /data /workspace/remediation /workspace/ansible \
    && chown -R autoheal:autoheal /workspace /data

COPY remediation/requirements.txt /workspace/remediation/requirements.txt
RUN pip install --no-cache-dir ansible-core -r /workspace/remediation/requirements.txt

COPY remediation/__init__.py /workspace/remediation/__init__.py
COPY remediation/src /workspace/remediation/src
COPY remediation/recover.yml /workspace/remediation/recover.yml
COPY ansible /workspace/ansible

USER autoheal

HEALTHCHECK --interval=15s --timeout=3s --retries=3 --start-period=10s \
    CMD python -c "import os, time, sys; p=os.getenv('AUTOHEAL_REMEDIATION_EXECUTOR_HEARTBEAT_PATH','/tmp/executor.heartbeat'); max_age=float(os.getenv('AUTOHEAL_REMEDIATION_EXECUTOR_POLL_INTERVAL','1'))*10+15; sys.exit(0 if os.path.exists(p) and (time.time()-os.path.getmtime(p))<max_age else 1)"

CMD ["python", "-m", "remediation.src.worker"]
