FROM python:3.12-slim AS builder

WORKDIR /usr/src/app

COPY ddns.py ddns.py

RUN apt-get update && apt-get install -y binutils
RUN pip install --no-cache-dir pyinstaller requests

RUN pyinstaller --onefile ddns.py

FROM debian:bookworm-slim AS runner

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y curl supervisor && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/dist/ddns /usr/src/app/ddns
COPY supervisord.conf /usr/src/app/supervisord.conf

EXPOSE 8044

ENV UPDATE_INTERVAL=600
ENV DOMAIN=demo.cn
ENV SUB_DOMAIN=ddns

HEALTHCHECK --interval=1m --timeout=10s --start-period=10s CMD curl --fail http://localhost:8044 || exit 1

ENTRYPOINT ["/usr/bin/supervisord", "-c", "/usr/src/app/supervisord.conf"]
