import logging
import queue
import numbers

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
        self.mqtt.on_message = self._on_mqtt_message
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

    def _on_connect(self, mqtt_client, userdata, flags, rc):
        '''callback for when the client receives a CONNACK response from the MQTT server.'''
        logging.info("Connected to MQTT broker with result code "+str(rc))
        # listen to enocean send requests
        for cur_sensor in self.sensors:
            mqtt_client.subscribe(cur_sensor['name']+'/req/#')

    def _on_mqtt_message(self, mqtt_client, userdata, msg):
        '''the callback for when a PUBLISH message is received from the MQTT server.'''
        # search for sensor
        for cur_sensor in self.sensors:
            if cur_sensor['name'] in msg.topic:
                # store data for this sensor
                if 'data' not in cur_sensor:
                    cur_sensor['data'] = {}
                prop = msg.topic[len(cur_sensor['name']+"/req/"):]
                cur_sensor['data'][prop] = int(msg.payload)


    def _read_packet(self, packet):
        '''interpret packet, read properties and publish to MQTT'''
        # search for fitting sensor
        found_property = False
        for cur_sensor in self.sensors:
            if packet.sender == cur_sensor['address']:
                if packet.type == PACKET.RADIO and packet.rorg == cur_sensor['rorg']:
                    properties = packet.parse_eep(cur_sensor['func'], cur_sensor['type'])
                    for prop_name in properties:
                        found_property = True
                        cur_prop = packet.parsed[prop_name]
                        if isinstance(cur_prop['value'], numbers.Number):
                            value = cur_prop['value']
                        else:
                            value = cur_prop['raw_value']
                        logging.info("{}: {} ({})={} {}".format(cur_sensor['name'], prop_name, cur_prop['description'], cur_prop['value'], cur_prop['unit']))
                        self.mqtt.publish(cur_sensor['name']+"/"+prop_name, value)
                    break
        if not found_property:
            logging.warn('message not interpretable: {}'.format(found_sensor['name']))
    
    
    def _reply_packet(self, packet, sensor):
        '''send enocean message as a reply to an incoming message'''
        logging.info('sending {} to {}'.format(sensor['data']['CV'], packet.sender))
        # self.enocean.send(Packet(PACKET.COMMON_COMMAND, [0x08]))


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

                # interpret packet, read properties and publish to MQTT
                self._read_packet(packet)
                
                # check for neccessary reply
                if 'data' in found_sensor:
                    self._reply_packet(packet, found_sensor)

            except queue.Empty:
                continue
