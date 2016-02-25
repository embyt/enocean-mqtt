import logging
import queue
import numbers

from enocean.communicators.serialcommunicator import SerialCommunicator
from enocean.protocol.packet import Packet, RadioPacket
from enocean.protocol.constants import PACKET, RORG, RETURN_CODE
import enocean.utils
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
        self.mqtt.on_disconnect = self._on_disconnect
        self.mqtt.on_message = self._on_mqtt_message
        if 'mqtt_user' in self.conf:
            logging.info("Authenticating: " + self.conf['mqtt_user'])
            self.mqtt.username_pw_set(self.conf['mqtt_user'], self.conf['mqtt_pwd'])
        self.mqtt.connect(self.conf['mqtt_host'], int(self.conf['mqtt_port'],0))
        self.mqtt.loop_start()

        # setup enocean communication
        self.enocean = SerialCommunicator(self.conf['enocean_port'])
        self.enocean.start()
        # setup default sender, which should not be needed because address is determined automatically
        self.enocean_sender = [ 255, 255, 0, 0 ]

    def __del__(self):
        if self.enocean is not None and self.enocean.is_alive():
            self.enocean.stop()

    def _on_connect(self, mqtt_client, userdata, flags, rc):
        '''callback for when the client receives a CONNACK response from the MQTT server.'''
        logging.info("Connected to MQTT broker with result code "+str(rc))
        # listen to enocean send requests
        for cur_sensor in self.sensors:
            mqtt_client.subscribe(cur_sensor['name']+'/req/#')

    def _on_disconnect(self, mqtt_client, userdata, rc):
        '''callback for when the client disconnects from the MQTT server.'''
        logging.warning("Disconnected from MQTT broker with code "+str(rc))

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
                if enocean.utils.combine_hex(packet.sender) == cur_sensor['address']:
                    # sensor configured in config file
                    if packet.packet_type == PACKET.RADIO and packet.rorg == cur_sensor['rorg']:
                        # radio packet of proper rorg type received; parse EEP
                        direction = cur_sensor['direction'] if 'direction' in cur_sensor else None
                        properties = packet.parse_eep(cur_sensor['func'], cur_sensor['type'], direction)
                        # loop through all EEP properties
                        for prop_name in properties:
                            found_property = True
                            cur_prop = packet.parsed[prop_name]
                            # we only extract numeric values, either the scaled ones or the raw values for enums
                            if isinstance(cur_prop['value'], numbers.Number):
                                value = cur_prop['value']
                            else:
                                value = cur_prop['raw_value']
                            # publish extracted information
                            logging.debug("{}: {} ({})={} {}".format(cur_sensor['name'], prop_name, cur_prop['description'], cur_prop['value'], cur_prop['unit']))
                            retain = 'persistent' in cur_sensor and cur_sensor['persistent']
                            self.mqtt.publish(cur_sensor['name']+"/"+prop_name, value, retain=retain)
                        break
            if not found_property:
                logging.warn('message not interpretable: {}'.format(found_sensor['name']))

        else:
            # learn request received
            logging.info("learn request received")


    def _reply_packet(self, in_packet, sensor):
        '''send enocean message as a reply to an incoming message'''
        # prepare addresses
        destination = in_packet.sender

        # prepare packet
        if 'direction' in sensor:
            # we invert the direction in this reply
            direction = 1 if sensor['direction'] == 2 else 2
        else:
            direction = None
        packet = RadioPacket.create(RORG.BS4, sensor['func'], sensor['type'], direction=direction,
                sender=self.enocean_sender, destination=destination, learn=in_packet.learn)

        # assemble data based on packet type (learn / data)
        if not in_packet.learn:
            # data packet received
            # start with default data
            packet.data[1:5] = [ (sensor['default_data'] >> i & 0xff) for i in (24,16,8,0) ]
            # do we have specific data to send?
            if 'data' in sensor:
                # override with specific data settings
                packet.set_eep(sensor['data'])
            else:
                # what to do if we have no data to send yet?
                logging.warn('sending default data as answer to %s', sensor['name'])

        else:
            # learn request received
            # copy EEP and manufacturer ID
            packet.data[1:5] = in_packet.data[1:5]
            # update flags to acknowledge learn request
            packet.data[4] = 0xf0

        # send it
        logging.info('sending: {}'.format(packet))
        self.enocean.send(packet)

    
    def _process_radio_packet(self, packet):
        # first, look whether we have this sensor configured
        found_sensor = False
        for cur_sensor in self.sensors:
            if enocean.utils.combine_hex(packet.sender) == cur_sensor['address']:
                found_sensor = cur_sensor
        
        # skip ignored sensors
        if found_sensor and 'ignore' in found_sensor and found_sensor['ignore']:
            return

        # log packet, if not disabled
        if self.conf['log_packets']:
            logging.info('received: {}'.format(packet))

        # abort loop if sensor not found
        if not found_sensor:
            logging.info('unknown sensor: {}'.format(enocean.utils.to_hex_string(packet.sender)))
            return

        # interpret packet, read properties and publish to MQTT
        self._read_packet(packet)
        
        # check for neccessary reply
        if 'answer' in found_sensor and found_sensor['answer']:
            self._reply_packet(packet, found_sensor)


    def run(self):
        # Request transmitter ID
        self.enocean_sender = self.enocean.base_id

        # start endless loop for listening
        while self.enocean.is_alive():
            # Loop to empty the queue...
            try:
                # get next packet
                packet = self.enocean.receive.get(block=True, timeout=1)
                
                # check packet type
                if packet.packet_type == PACKET.RADIO:
                    self._process_radio_packet(packet)
                elif packet.packet_type == PACKET.RESPONSE:
                    response_code = RETURN_CODE(packet.data[0])
                    logging.info("got response packet: {}".format(response_code.name))
                else:
                    logging.info("got non-RF packet: {}".format(packet))
                    continue
            except queue.Empty:
                continue
