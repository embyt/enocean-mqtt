#!/usr/bin/env python3
import logging
import sys
import traceback
from configparser import ConfigParser
import queue

from enocean.communicators.serialcommunicator import SerialCommunicator
from enocean.protocol.packet import Packet
from enocean.protocol.constants import PACKET, RORG
import paho.mqtt.client as mqtt


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
        new_sens = {'name': conf['DEFAULT']['mqtt_prefix'] + section}
        for key in ('address', 'rorg', 'func', 'type'):
            new_sens[key] = int(conf[section][key], 0)
        sensors.append(new_sens)
    # general configuration is part of DEFAULT section
    return sensors, conf['DEFAULT']

def on_mqtt_connect(client, userdata, flags, rc):
    '''callback for when the client receives a CONNACK response from the MQTT server.'''
    logging.info("Connected to MQTT broker with result code "+str(rc))


# init logging
logging.basicConfig(level=logging.DEBUG)

# load config file
sensors, conf = load_config_file()

# setup mqtt connection
mqtt = mqtt.Client()
mqtt.on_connect = on_mqtt_connect
mqtt.connect(conf['mqtt_host'], int(conf['mqtt_port'],0))
mqtt.loop_start()

# setup enocean communication
enocean = SerialCommunicator(conf['enocean_port'])
enocean.start()

while enocean.is_alive():
    try:
        # Loop to empty the queue...
        packet = enocean.receive.get(block=True, timeout=1)
        # search for fitting sensor
        found_sensor = False
        for cur_sensor in sensors:
            if packet.type == PACKET.RADIO and packet.rorg == cur_sensor['rorg'] and \
                    packet.sender == cur_sensor['address']:
                for cur_prop in packet.parse_eep(cur_sensor['func'], cur_sensor['type']):
                    logging.debug("{}={}".format(cur_sensor['name'], packet.parsed[cur_prop]['value']))
                    mqtt.publish(cur_sensor['name'], packet.parsed[cur_prop]['value'])
                found_sensor = True
                break
        if not found_sensor:
            print('sensor not found: %s' % packet)

    except queue.Empty:
        continue
    except KeyboardInterrupt:
        break
    except Exception:
        traceback.print_exc(file=sys.stdout)
        break

if enocean.is_alive():
    enocean.stop()
