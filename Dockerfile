FROM pypy:3-slim

VOLUME /config

COPY . /
RUN chmod +x /docker-entrypoint.sh && pypy3 setup.py develop

WORKDIR /config
ENTRYPOINT /docker-entrypoint.sh
