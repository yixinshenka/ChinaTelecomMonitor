FROM python:3.13-alpine

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

ENV TZ="Asia/Shanghai"

ARG BUILD_SHA
ARG BUILD_TAG
ENV BUILD_SHA=$BUILD_SHA
ENV BUILD_TAG=$BUILD_TAG
ENV WHITELIST_NUM=

EXPOSE 10000

CMD ["python", "./app/api_server.py"]
