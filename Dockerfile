FROM python:3.6-alpine3.8

VOLUME /config

ENV TZ="Europe/Paris"

RUN apk add tzdata
RUN echo "${TZ}" > /etc/timezone
RUN cp /usr/share/zoneinfo/${TZ} /etc/localtime

COPY . /
RUN python setup.py develop

WORKDIR /
ENTRYPOINT ["python", "/usr/local/bin/enoceanmqtt", "/config/enoceanmqtt.conf"]
