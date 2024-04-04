#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ELAN 04F3:0C4C Match-on-Chip fingerprint reader driver PoC.

Usage:
    ARGV0 -h | --help
    ARGV0 info
    ARGV0 soft_reset
    ARGV0 hard_reset
    ARGV0 finger_info <id>
    ARGV0 verify
    ARGV0 enrolled_count
    ARGV0 enroll (-u UD)
    ARGV0 delete <id>
    ARGV0 finger_info_all
    ARGV0 delete_all
    ARGV0 wipe_all
    ARGV0 fw_ver
    ARGV0 read_reg <reg>
    ARGV0 dump_regs
    ARGV0 raw (-e EP) <hex>...

Options:
-h, --help         Show help
-e EP, --ep-in EP  Input endpoint for raw commands
-u UD. --user UD   User data for enroll command

Commands:
info               Get device info
soft_reset         Reset sensor (via libusb)
hard_reset         Reset sensor (via hardware - disconnect and reconnect)
finger_info <id>   Get finger info
verify             Verify finger
enrolled_count     Get number of fingers currently enrolled
enroll             Enroll a new finger
delete <id>        Delete finger
delete_all         Delete all enrolled fingers (one by one)
wipe_all           Wipe all enrolled fingers (using special command)
fw_ver             Get firmware version
read_reg <reg>     Read register
dump_regs          Read all registers
raw                Send raw command
"""
import struct
import sys
import warnings
from collections import namedtuple
from typing import Optional

import hexdump
import usb1
from docopt import docopt

Command = namedtuple("Command", ("command", "out_len", "in_len", "ep_out", "ep_in"))

COMMANDS = {
    "reset_device": Command(b"'WDTRST", 8, 0, 1, None),
    "fw_ver": Command(b"\x19", 2, 2, 1, 3),
    "verify": Command(b"\xff\x03", 3, 2, 1, 4),
    "finger_info": Command(b"\xff\x12", 4, 70, 1, 3),
    "enrolled_num": Command(b"\xff\x04", 3, 2, 1, 3),
    "enrolled_num1": Command(b"\xff\x00", 3, 2, 1, 3),
    "abort": Command(b"\xff\x02", 3, 2, 1, 3),
    "commit": Command(b"\xff\x11", 72, 2, 1, 3),
    "enroll": Command(b"\xff\x01", 7, 2, 1, 4),
    "check_enrolled_collision": Command(b"\xff\x10", 3, 3, 1, 3),
    "delete_subsid": Command(b"\xff\x13", 72, 2, 1, 3),
    "delete": Command(b"\xff\x05", 5, 2, 1, 3),
    "wipe_all": Command(b"\xff\x99", 3, 0, 1, None),
}

# --- @'WDTRST
# 00 09
# 40  FF 05 xx yy
# 02 \n
# 01 \n

# --- 40 40+X    # read register X                         # resp: 1  # 64 registers
# 40 80+X Y  # write register X with value Y
# 42 01 52 55 4E 49 41 50   # switch to bootloader
# 01 0A      # get raw (14 bit) image?
# 40 19      # get bridge firmware version             # resp: 2
# 00 C0      # get sensor trace                        # resp: 4
# 40 13      # get sensor status                       # resp: 1
# 00 09      # capture start (get image)
# 40 FF 05 XX YY  # remove finger?                     # resp: 2
# 02 0A      # get 8bit img?  (rotate if w=52 h=150)
# 40 ff 14 XX  # set fw sensor mode                    # resp: 4  0 = normal WBF mode, 1 = VBS WBF mode
# 00 10 0/1  # set EC pin state

# 40 FF 0A ?? (35 bytes)  # ecc enroll committed??     # resp: 2


ERRORS = {
    0x41: "Move slightly downwards",
    0x42: "Move slightly to the right",
    0x43: "Move slightly upwards",
    0x44: "Move slightly to the left",
    0xfb: "Sensor is dirty or wet",
    0xfd: "Finger not enrolled",
    0xfe: "Finger area not enough",
    0xdd: "Maximum number of enrolled fingers reached"
}

DEVICES = (
    (0x04f3, 0x0c00),  # HP Pavilion 15-eh2xxx
    (0x04f3, 0x0c4c),  # HP Spectre x360 14-ea0x
    (0x04f3, 0x0c5e),  # HP Probook 440 G8
)
IFACE = 0


def command(usb: usb1.USBDeviceHandle, cmdname: str, payload: bytes = b"", timeout=5000) -> bytes:
    outpayload, outlen, inlen, ep_out, ep_in = COMMANDS[cmdname]
    cmd = b"\x40" + outpayload + payload
    if len(cmd) != outlen:
        warnings.warn(f"Wrong command size: {len(cmd)} vs {outlen}")

    usb.bulkWrite(ep_out, cmd, timeout)

    if inlen == 0 or ep_in is None:
        return b""

    resp = usb.bulkRead(ep_in, inlen, timeout)

    if len(resp) < inlen:
        warnings.warn(f"Device replied with shorter answer: {len(cmd)} vs {inlen}")

    return resp


def read_register(usb: usb1.USBDeviceHandle, reg: int) -> int:
    if not 0 <= reg < 64:
        raise ValueError("Register out of range (0-63)")
    cmd = b"\x40" + bytes([0x40 + reg])

    usb.bulkWrite(1, cmd)
    resp = usb.bulkRead(3, 2)

    if len(resp) != 2:
        warnings.warn(f"Device replied with wrong size: {len(resp)}")

    error = get_error(resp[1])
    if error:
        raise IOError(f"Failing to read register {reg}: {error}")

    return resp[0]


def get_error(byte: int) -> Optional[str]:
    # Very eyeballed
    if (byte & 0xF0) == 0:
        return None
    if byte not in ERRORS:
        return f"Unknown error {hex(byte)}"
    return ERRORS[byte]


def enroll(handle: usb1.USBDeviceHandle, user_data: bytes):
    resp = command(handle, "enrolled_num")
    error = get_error(resp[1])
    if error:
        print(f"Failed to retrieve currently enrolled fingers: {error}")
        return
    new_finger_id = enrolled = resp[1]
    print(f"Enrolled fingers: {enrolled}")

    while True:
        print("Place finger on reader")
        resp = command(handle, "verify", timeout=5000)
        error = get_error(resp[1])
        if not error:
            print(f"Finger already enrolled: {resp[1]}")
            continue
        if resp[1] != 0xfd:  # Not enrolled
            print(f"Error: {error}")
            continue
        print("Proceeding")
        break

    total_attempts = 8
    attempts_done = 0
    while attempts_done < total_attempts:
        print(f"Place finger on reader [{attempts_done + 1}/{total_attempts}]")
        payload = struct.pack("BBBB", new_finger_id, total_attempts, attempts_done, 0)
        resp = command(handle, "enroll", payload, timeout=10000)
        error = get_error(resp[1])
        if resp[1] != 0:
            print(f"Error: {error} ({hex(resp[1])})")
            if resp[1] == 0xdd:
                return  # Max fingers
            continue
        attempts_done += 1

    resp = command(handle, "check_enrolled_collision")
    if resp[1] != 0:
        colliding_finger = resp[2]
        print(f"Error: Finger was already enrolled as finger {colliding_finger}")
        return

    print("No collisions detected, committing enrolled finger")
    payload = (struct.pack("B", 0xf0 | (new_finger_id + 5)) + user_data).ljust(69, b"\x00")
    resp = command(handle, "commit", payload)
    if resp[1] == 0:
        print("Enroll successful 🎉")
    else:
        print(f"Sensor is angry: {resp.hex(' ')}")


def verify(handle: usb1.USBDeviceHandle) -> int:
    while True:
        print("Place finger on reader")
        resp = command(handle, "verify", timeout=5000)
        error = get_error(resp[1])
        if error:
            print(error)
            continue
        print(f"Recognized finger: {resp[1]}")
        return resp[1]


def get_finger_info(handle: usb1.USBDeviceHandle, finger_id: int) -> bytes:
    while True:
        resp = command(handle, "finger_info", finger_id.to_bytes(1, "little"))
        if resp[1] == 0xff:
            print("Sensor is angry, verify a finger to calm it down")
            verify(handle)
            continue
        if len(resp) == 2:
            raise IOError(f"Error: {get_error(resp[1])}")
        return resp


def delete_by_id(handle: usb1.USBDeviceHandle, fpid: int):
    payload = bytes([fpid, 0])
    resp = command(handle, "delete", payload)
    error = get_error(resp[1])
    if resp[1] != 0:
        print(f"Error: {error} ({hex(resp[1])})")
    else:
        print("Deleted, finger info:")
        resp = get_finger_info(handle, fpid)
        hexdump.hexdump(resp)


def delete(handle: usb1.USBDeviceHandle, fpid: int, finger_sid: bytes):
    resp = command(handle, "delete_subsid", finger_sid)
    error = get_error(resp[1])
    if resp[1] != 0:
        print(f"Error: {error} ({hex(resp[1])})")
    else:
        print("Deleted, finger info:")
        resp = get_finger_info(handle, fpid)
        hexdump.hexdump(resp)


def main(args):
    with usb1.USBContext() as context:
        for vid, pid in DEVICES:
            handle = context.openByVendorIDAndProductID(vid, pid)
            if handle:
                break
        else:
            raise OSError("Failed to open USB device")

        with handle.claimInterface(IFACE):
            try:
                if args["soft_reset"]:
                    handle.resetDevice()

                elif args["hard_reset"]:
                    command(handle, "reset_device")
                    print("Device reset.")

                elif args["info"]:
                    dev: usb1.USBDevice = handle.getDevice()
                    print("Bus:", dev.getBusNumber())
                    print("Address:", dev.getDeviceAddress())
                    print("VID:PID: %04x:%04x" % (dev.getVendorID(), dev.getProductID()))
                    print("Manufacturer:", dev.getManufacturer())
                    print("Product:", dev.getProduct())
                    print("Serial number:", dev.getSerialNumber())

                    resp = command(handle, "fw_ver")
                    print(f"Firmware version: {resp[0]}.{resp[1]}")

                elif args["verify"]:
                    verify(handle)

                elif args["fw_ver"]:
                    resp = command(handle, "fw_ver")
                    print(f"Version: {resp[0]}.{resp[1]}")

                elif args["finger_info"]:
                    finger_id = int(args["<id>"])
                    resp = get_finger_info(handle, finger_id)
                    print("Finger info:")
                    hexdump.hexdump(resp)

                elif args["finger_info_all"]:
                    for finger_id in range(10):
                        resp = get_finger_info(handle, finger_id)
                        print(f"Finger info {finger_id}:")
                        hexdump.hexdump(resp)

                elif args["enrolled_count"]:
                    resp = command(handle, "enrolled_num")
                    print(f"Enrolled fingers: {resp[1]}")

                elif args["enroll"]:
                    enroll(handle, args["--user"].encode())

                elif args["raw"]:
                    ep = int(args["--ep-in"])
                    payload = bytes(map(lambda x: int(x, 16), args["<hex>"]))
                    print(f"Sending [{len(payload)}]:")
                    hexdump.hexdump(payload)
                    print()
                    handle.bulkWrite(1, payload, timeout=5000)
                    print("Waiting for response...")
                    resp = handle.bulkRead(ep, 1000, timeout=5000)
                    print(f"Received [{len(resp)}]:")
                    hexdump.hexdump(resp)

                elif args["delete"]:
                    finger_id = int(args["<id>"])
                    delete_by_id(handle, finger_id)

                elif args["delete_all"]:
                    for finger_id in range(10):
                        resp = get_finger_info(handle, finger_id)
                        if resp[-1] == 0xff:
                            print(f"Finger {finger_id} not enrolled")
                            continue
                        payload = (struct.pack("B", 0xf0 | (finger_id + 5)) + resp[2:]).ljust(69, b"\x00")
                        delete(handle, finger_id, payload)

                elif args["wipe_all"]:
                    print("Wiping all fingers")
                    command(handle, "wipe_all")
                    print("Checking if all fingers are wiped (~5 seconds)")
                    resp = command(handle, "enrolled_num", timeout=10000)
                    print(f"Enrolled fingers: {resp[1]}")

                elif args["read_reg"]:
                    reg = int(args["<reg>"])
                    print(f"Register {reg}: {read_register(handle, reg):#02x}")

                elif args["dump_regs"]:
                    # Print a 8x8 table of registers
                    print("     x0  x1  x2  x3  x4  x5  x6  x7\n")
                    for i in range(8):
                        print(f"{i}x ", end="")
                        for j in range(8):
                            print(f"  {read_register(handle, i * 8 + j) :02x}", end="")
                        print()

            except (Exception, KeyboardInterrupt) as e:
                print("Aborting")
                handle.bulkWrite(1, b"\40" + COMMANDS["abort"].command)
                raise


if __name__ == '__main__':
    args = docopt(__doc__.replace("ARGV0", sys.argv[0]))
    main(args)
