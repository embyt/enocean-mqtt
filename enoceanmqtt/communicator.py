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
        if not packet.learn:
            # data packet received
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
    
        else:
            # learn request received
            logging.info("learn request received")


    def _reply_packet(self, packet, sensor):
        '''send enocean message as a reply to an incoming message'''
        p = Packet(PACKET.RADIO)
        sender = [ (int(self.conf['enocean_sender'], 0) >> i & 0xff) for i in (24,16,8,0) ]
        status = 0  # not repeated
        
        # assemble data based on packet type (learn / data)
        if not packet.learn:
            # data packet received
            # start with default data
            data = [ (sensor['default_data'] >> i & 0xff) for i in (24,16,8,0) ]
            # temporary override data
            #data[0] = 100
        else:
            # learn request received
            # copy packet content from request
            data = packet.data[1:5]
            # update flags to acknowledge learn request
            data[3] = 0xf0

        # optional data
        sub_tel_num = 3
        destination = [ 255, 255, 255, 255 ]    # broadcast
        dbm = 0xff
        security = 0

        # assemble packet
        p.data = [ packet.rorg ] + data + sender + [ status ]
        p.optional = [ sub_tel_num ] + destination + [ dbm ] + [ security ]

        # send it
        logging.info('sending: {}'.format(p))
        self.enocean.send(p)


    def run(self):
        while self.enocean.is_alive():
            # Loop to empty the queue...
            try:
                # get next packet
                packet = self.enocean.receive.get(block=True, timeout=1)
                
                # check packet type
                if packet.type != PACKET.RADIO:
                    logging.info("got non-RF packet: {}".format(packet))
                    continue
                
                # first, look whether we have this sensor configured
                found_sensor = False
                for cur_sensor in self.sensors:
                    if packet.sender == cur_sensor['address']:
                        found_sensor = cur_sensor
                
                # skip ignored sensors
                if found_sensor and 'ignore' in found_sensor and found_sensor['ignore']:
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
                if 'answer' in found_sensor and found_sensor['answer']:
                    self._reply_packet(packet, found_sensor)

            except queue.Empty:
                continue
