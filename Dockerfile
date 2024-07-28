
FROM python:3.12-slim AS builder


WORKDIR /usr/src/app


COPY . .


RUN apt-get update && apt-get install -y binutils

RUN pip install --no-cache-dir pyinstaller requests


RUN pyinstaller --onefile ddns.py


FROM debian:bookworm-slim AS runner


WORKDIR /usr/src/app


COPY --from=builder /usr/src/app/dist/ddns /usr/src/app/ddns


EXPOSE 8044


ENV PROVIDER=dnspod
ENV UPDATE_INTERVAL=600
ENV DOMAIN=demo.cn
ENV SUB_DOMAIN=ddns


HEALTHCHECK --interval=1m --timeout=10s --start-period=10s CMD curl --fail http://localhost:8044 || exit 1

VOLUME ["/usr/src/app"]

CMD ["/usr/src/app/ddns"]
