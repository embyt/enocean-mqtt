FROM python:3.6-alpine3.8

VOLUME /config

COPY . /
RUN python setup.py develop

WORKDIR /
ENTRYPOINT ["python", "/usr/local/bin/enoceanmqtt", "/enoceanmqtt-default.conf /config/enoceanmqtt.conf"]
