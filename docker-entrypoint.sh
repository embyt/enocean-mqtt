#!/bin/bash

mv -n /enoceanmqtt.conf /config/enoceanmqtt.conf && pypy3 /usr/local/bin/enoceanmqtt
