FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --gid 10001 autoheal \
    && useradd --uid 10001 --gid 10001 --create-home --shell /sbin/nologin autoheal \
    && mkdir -p /data \
    && chown -R autoheal:autoheal /app /data

COPY api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY api/src /app/src

USER autoheal

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --retries=3 --start-period=10s \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]

