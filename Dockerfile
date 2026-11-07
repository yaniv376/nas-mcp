FROM python:3.12-alpine

RUN apk add --no-cache tzdata

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY nasmcp ./nasmcp

ARG VERSION=dev
ARG BUILD_DATE=""
ENV NASMCP_DATA_DIR=/data \
    NASMCP_PORT=8790 \
    NASMCP_VERSION=$VERSION \
    NASMCP_BUILD_DATE=$BUILD_DATE \
    PYTHONUNBUFFERED=1

# Unprivileged by default; docker-compose.yml runs it as your DSM user.
RUN mkdir -p /data && chmod 777 /data
USER 1026:100
VOLUME ["/data"]
EXPOSE 8790

HEALTHCHECK --interval=60s --timeout=5s CMD wget -qO- http://127.0.0.1:${NASMCP_PORT}/health || exit 1

CMD ["python", "-m", "nasmcp.main"]
