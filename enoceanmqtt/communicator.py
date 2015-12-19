import logging
import queue

from enocean.communicators.serialcommunicator import SerialCommunicator
from enocean.protocol.packet import Packet
from enocean.protocol.constants import PACKET, RORG
import paho.mqtt.client as mqtt


class Communicator:
    mqtt = None
    enocean = None

    def __init__(self, config, sensors):
        self.conf = config
        self.sensors = sensors
        
        # setup mqtt connection
        self.mqtt = mqtt.Client()
        self.mqtt.on_connect = self._on_connect
        if 'mqtt_user' in self.conf:
            logging.info("Authenticating: " + self.conf['mqtt_user'])
            self.mqtt.username_pw_set(self.conf['mqtt_user'], self.conf['mqtt_pwd'])
        self.mqtt.connect(self.conf['mqtt_host'], int(self.conf['mqtt_port'],0))
        self.mqtt.loop_start()

        # setup enocean communication
        self.enocean = SerialCommunicator(self.conf['enocean_port'])
        self.enocean.start()

    def __del__(self):
        if self.enocean is not None and self.enocean.is_alive():
            self.enocean.stop()

    def _on_connect(self, client, userdata, flags, rc):
        '''callback for when the client receives a CONNACK response from the MQTT server.'''
        logging.info("Connected to MQTT broker with result code "+str(rc))


    def run(self):
        while self.enocean.is_alive():
            # Loop to empty the queue...
            try:
                # get next packet
                packet = self.enocean.receive.get(block=True, timeout=1)
                
                # first, look whether we have this sensor configured
                found_sensor = False
                for cur_sensor in self.sensors:
                    if packet.sender == cur_sensor['address']:
                        found_sensor = cur_sensor
                
                # skip ignored sensors
                if found_sensor and found_sensor['ignore']:
                    continue

                # log packet, if not disabled
                if self.conf['log_packets']:
                    logging.info('received: {}'.format(packet))

                # abort loop if sensor not found
                if not found_sensor:
                    logging.info('unknown sensor: {}'.format(hex(packet.sender)))
                    continue

                # search for fitting sensor
                found_property = False
                for cur_sensor in self.sensors:
                    if packet.sender == cur_sensor['address']:
                        if packet.type == PACKET.RADIO and packet.rorg == cur_sensor['rorg']:
                            properties = packet.parse_eep(cur_sensor['func'], cur_sensor['type'])
                            for prop_name in properties:
                                found_property = True
                                cur_prop = packet.parsed[prop_name]
                                logging.info("{}: {}={} {}".format(cur_sensor['name'], cur_prop['description'], cur_prop['value'], cur_prop['unit']))
                                self.mqtt.publish(cur_sensor['name']+"/raw", cur_prop['raw_value'])
                                self.mqtt.publish(cur_sensor['name']+"/value", cur_prop['value'])
                                self.mqtt.publish(cur_sensor['name']+"/dbm", packet.dBm)
                            break
                if not found_property:
                    logging.warn('message not interpretable: {}'.format(found_sensor['name']))

            except queue.Empty:
                continue
