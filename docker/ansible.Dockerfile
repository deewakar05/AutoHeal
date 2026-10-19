FROM python:3.12-alpine

RUN apk add --no-cache docker-cli \
    && pip install --no-cache-dir ansible-core docker requests

WORKDIR /workspace/ansible

CMD ["sleep", "infinity"]
