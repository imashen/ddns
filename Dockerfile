FROM python:3.12-slim

WORKDIR /usr/src/app

COPY . .

RUN pip install --no-cache-dir requests

EXPOSE 80

ENV PROVIDER=dnspod
ENV UPDATE_INTERVAL=600
ENV DOMAIN=demo.cn
ENV SUB_DOMAIN=ddns

HEALTHCHECK --interval=1m --timeout=10s --start-period=30s CMD curl --fail http://localhost:80 || exit 1

CMD ["python", "./ddns.py"]