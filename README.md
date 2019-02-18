# EnOcean to MQTT Forwarder #

This Python module receives messages from an EnOcean interface (e.g. via USB) and publishes selected messages to an MQTT broker.

You may also configure it to answer to incoming EnOcean messages with outgoing responses. The response content is also defined using MQTT requests.

It builds upon the [Python EnOcean](https://github.com/kipe/enocean) library.

## Installation ##

 - download this repository to an arbritary directory
 - install it using `python3 setup.py develop`
 - adapt the `enoceanmqtt.conf.sample` file and put it to /etc/enoceanmqtt.conf
   - set the enocean interface port
   - define the MQTT broker address
   - define the sensors to monitor
 - ensure that the MQTT broker is running
 - run `enoceanmqtt` from within the directory of the config file or provide the config file as a command line argument

### Setup as a daemon ###

Assuming you want this tool to run as a daemon, which get automatically started by systemd:
 - copy the `enoceanmqtt.service` to `/etc/systemd/system/` (making only a symbolic link [will not work](https://bugzilla.redhat.com/show_bug.cgi?id=955379))
 - `systemctl enable enoceanmqtt`
 - `systemctl start enoceanmqtt`

### Setup as a docker container ###

- Mount the `/config` volume and your enocean USB device
- Adapt the `enoceanmqtt.conf` file in the `/config` folder

### Define persistant device name for EnOcean interface ###

If you own an USB EnOcean interface and use it together with some other USB devices you may face the situation that the EnOcean interface gets different device names depending on your plugging and unplugging sequence, such as `/dev/ttyUSB0`or `/dev/ttyUSB1`. You would need to always adapt your config file then.

To solve this you can make an udev rule that assigns a symbolic name to the device. For this, create the file `/etc/udev/rules.d/99-usb.rules` with the following content:

`SUBSYSTEM=="tty", ATTRS{product}=="EnOcean USB 300 DB", SYMLINK+="enocean"`

After reboot, this assigns the symbolic name `/dev/enocean`. If you use a different enocean interface, you may want to check the product string by looking into `dmesg` and search for the corresponding entry here. Alternatively you can check `udevadm info -a -n /dev/ttyUSB0`, assuming that the interface is currently mapped to `ttyUSB0`.

## Configuration ##

Please take a look at the provided [enoceanmqtt.conf](enoceanmqtt.conf) sample config file. Most should be self explaining.

Multiple config files can be specified as command line arguments. Values are merged, later config files override values of the former. This is the order:

* `/etc/enoceanmqtt.conf`
* in Dockerfile: `/enoceanmqtt-default.conf`, compare [enoceanmqtt-default.conf](enoceanmqtt-default.conf).
* any further command line argument.

This can be used to split security sensitive values from the device configs.

### Answering EnOcean Messages ###

To answer EnOcean messages you configure the `answer` switch and the `default_data` in the config file. To customize the response data you publish an MQTT message to the sensor topic where you prefix the topic with `/req`.

An example: If you want to set the valve position (set point) of a heating actuator named `heating` (e.g. with `rorg = 0xA5`, `func = 0x20`, `type = 0x01`) to 80 % you publish the integer value 80 to the topic `enocean/heating/req/SP`. This replaces the corresponding part of `default_data`.
