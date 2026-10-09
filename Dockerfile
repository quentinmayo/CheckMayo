FROM alpine:3.23 AS opa
ARG TARGETARCH
ARG OPA_VERSION=1.21.1
RUN apk add --no-cache curl && \
    curl -fsSL "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_${TARGETARCH}_static" -o /opa && \
    curl -fsSL "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_${TARGETARCH}_static.sha256" -o /opa.sha256 && \
    echo "$(cut -d ' ' -f1 /opa.sha256)  /opa" | sha256sum -c - && chmod 755 /opa
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 CHECKMAYO_STATE_DIR=/data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && groupadd -g 10001 checkmayo && useradd -u 10001 -g checkmayo -M checkmayo && mkdir /data && chown checkmayo:checkmayo /data
COPY --from=opa /opa /usr/local/bin/opa
COPY app app
COPY scanners scanners
COPY scripts/opa-capabilities.py /tmp/opa-capabilities.py
RUN python /tmp/opa-capabilities.py && rm /tmp/opa-capabilities.py
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=4)"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
