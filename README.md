# EnOcean to MQTT Forwarder #

This Python module receives messages from an EnOcean interface (e.g. via USB) and publishes selected messages to an MQTT broker.

It builds upon the [EnOcean Sensor Kit](https://github.com/kipe/enocean) library.

## Install ##

 - download this repository to an arbritary directory
 - run `python3 setup.py develop`
 - adapt the enoceanmqtt.conf configuration file
   - set enocean interface port
   - define the MQTT broker address
   - define the sensors to receive
 - ensure that the MQTT broker is running
 - run `enoceanmqtt` from within the directory of the config file or provide the config file as a command line argument

### Setting up as a daemon ###

Assuming you want this tool to run as a daemon, which get automatically started by systemd: 
 - copy the `enoceanmqtt.service` to `/etc/systemd/system/` (making a symbolic link [will not work](https://bugzilla.redhat.com/show_bug.cgi?id=955379))
 - `systemctl enable enoceanmqtt`
 - `systemctl start enoceanmqtt`

### Define persistant device name for EnOcean interface ###

If you own an USB EnOcean interface and use it (as me) together with some other USB devices you may face the situation that the EnOcean interface gets different device names depending on your plugging and unplug sequence, such as `/dev/ttyUSB0`or `/dev/ttyUSB1`. You would need to always adapt your config file then.

To solve this you can make an udev rule that assigns a symbolic name to the device. For this, create the file `/etc/udev/rules.d/99-usb.rules` with the following content:

`SUBSYSTEM=="tty", ATTRS{product}=="EnOcean USB 300 DB", SYMLINK+="enocean"`

This assignes the symbolic name `/dev/enocean`. You may want to check the product string looking into `dmesg` and scan for the corresponding entry here. Alternatively you can check `udevadm info -a -n /dev/ttyUSB0`, assuming that the interface is currently mapped to `ttyUSB0`.
