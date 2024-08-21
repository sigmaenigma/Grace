# Grace
Grace is a python based script to monitor your network and gracefully shut down servers if certain thresholds are met.

The purpose of this program is to properly and "grace"fully shut down servers on a LAN if a power outage
has been detected. The method to detect if an outage has occured is to monitor a known LAN device running
that's connected to a wall outlet (e.g. a WiFi plug) and then if offline, to run an SSH connection to a device 
that is also not on a power backup. If that login fails, the program then decides to scan the network(s) and if
wireless devices are not detected and WAN access is down, it can be assumed that power is off to devices
not on backup power (this includes access points). From there, devices that are on backup power should be
gracefully shutdown using appropriate commands. 

This script sends shutdown signals to Linux servers and Synology servers given the proper configurations are
set in the configuration file (config.json)

For Linux servers, the assumption is that the same user has been created across the devices. For Synology,
one will need to create the appropriate API access in order to shutdown the server. One could also log into the
Synology server and shut it down via SSH.
