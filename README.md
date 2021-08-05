# ELAN 04f3:0c4c communication PoC

This repository hosts a PoC implementing the communication for the fingerprint sensor found in
the 2020 HP Spectre x360 14".

The protocol so far seems to be very similar to that of 04f4:0c7e, already supported by
libfprint: [`elanmoc.c`](https://gitlab.freedesktop.org/libfprint/libfprint/-/blob/master/libfprint/drivers/elanmoc/elanmoc.c)

However there seem to be some differences.

## Dissection parser

`wireshark_parser.py` parses a WireShark dissection of the communication with the sensor,
output as JSON.

In case there are any differences between platforms, since I was not able to make the sensor
run in a VM, I collected all captures [from Windows with USBPcap](https://wiki.wireshark.org/CaptureSetup/USB#Windows).

To output the dissection, first make sure there are no `URB_BULK` packets that are reported as
"malformed". Disable all incriminated dissector as needed from `Analyze` > `Enabled Protocols...`.
`IPPUSB` seems to be the culprit.

Then, after making sure **all** packets referring to the device are **not** filtered, export
the JSON from `File` > `Export Packet Dissections` > `As JSON...`.

## Wireshark dissector

A simple WireShark dissector is also provided. It's very basic.

It can be dropped into the Lua plugins directory, then you can right-click a packet and select
"Decode as..." > ELANMOC.

## Actual PoC

To be written

## License

MIT
