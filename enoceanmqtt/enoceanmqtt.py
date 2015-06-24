#!/usr/bin/env python3
import logging
import sys
import traceback
from configparser import ConfigParser
import queue

from enocean.communicators.serialcommunicator import SerialCommunicator
from enocean.protocol.packet import Packet
from enocean.protocol.constants import PACKET, RORG


def load_config_file():
    conf = ConfigParser(inline_comment_prefixes=('#', ';'))
    if len(sys.argv) > 1:
        conf.read(sys.argv[1])
    else:
        # try default config file name
        conf.read("enoceanmqtt.conf")
    # extract sensor configuration
    sensors = []
    for section in conf.sections():
        if section != 'DEFAULT':
            new_sens = {
                'address': int(conf[section]['address'], 0),
                'rorg': int(conf[section]['rorg'], 0),
                'func': int(conf[section]['func'], 0),
                'type': int(conf[section]['type'], 0),
            }
            sensors.append(new_sens)
    # general configuration is part of DEFAULT section
    return sensors, conf['DEFAULT']


# init logging
logging.basicConfig(level=logging.DEBUG)

# load config file
sensors, conf = load_config_file()

# setup enocean communication
enocean = SerialCommunicator(conf['enocean_port'])
enocean.start()

while enocean.is_alive():
    try:
        # Loop to empty the queue...
        p = enocean.receive.get(block=True, timeout=1)
        # search for fitting sensor
        found_sensor = False
        for cur_sensor in sensors:
            if p.type == PACKET.RADIO and p.rorg == cur_sensor['rorg'] and \
                    p.sender == cur_sensor['address']:
                for k in p.parse_eep(cur_sensor['func'], cur_sensor['type']):
                    print('%s: %s' % (k, p.parsed[k]))
                found_sensor = True
                break
        if not found_sensor:
            print('sensor not found: %s' % p)

    except queue.Empty:
        continue
    except KeyboardInterrupt:
        break
    except Exception:
        traceback.print_exc(file=sys.stdout)
        break

if enocean.is_alive():
    enocean.stop()
