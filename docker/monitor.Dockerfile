FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/workspace

WORKDIR /workspace

RUN addgroup -g 10001 -S autoheal \
    && adduser -u 10001 -S -G autoheal \
       -h /tmp/autoheal-home -s /sbin/nologin autoheal \
    && mkdir -p /data /workspace/remediation \
    && chown -R autoheal:autoheal /workspace /data

COPY remediation/requirements.txt /workspace/remediation/requirements.txt

RUN pip install --no-cache-dir \
    -r /workspace/remediation/requirements.txt

COPY remediation/__init__.py /workspace/remediation/__init__.py
COPY remediation/src /workspace/remediation/src

USER autoheal

CMD ["python", "-m", "remediation.src.monitor_service"]
