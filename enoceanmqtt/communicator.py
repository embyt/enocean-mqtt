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
            try:
                # Loop to empty the queue...
                packet = self.enocean.receive.get(block=True, timeout=1)
                # search for fitting sensor
                found_sensor = False
                for cur_sensor in self.sensors:
                    if packet.type == PACKET.RADIO and packet.rorg == cur_sensor['rorg'] and \
                            packet.sender == cur_sensor['address']:
                        properties = packet.parse_eep(cur_sensor['func'], cur_sensor['type'])
                        for prop_name in properties:
                            cur_prop = packet.parsed[prop_name]
                            logging.debug("{}={}".format(cur_sensor['name'], cur_prop['value']))
                            self.mqtt.publish(cur_sensor['name'], cur_prop['value'])
                        found_sensor = True
                        break
                if not found_sensor:
                    logging.warn('sensor not found: {}'.format(packet))

            except queue.Empty:
                continue
