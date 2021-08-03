#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import sys
import typing
import warnings

import pyjq as jq

ID_VENDOR = 0x04f3
ID_PRODUCT = 0x0c4c


class Colors:
    """ ANSI color codes """
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    BROWN = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    LIGHT_GRAY = "\033[0;37m"
    DARK_GRAY = "\033[1;30m"
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_PURPLE = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"
    LIGHT_WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    CROSSED = "\033[9m"
    END = "\033[0m"


def find_bus_device(j: list) -> tuple:
    device_descs = jq.all('map(._source.layers) | map(select(. | has("DEVICE DESCRIPTOR"))) | .[]', j)
    if not device_descs:
        raise ValueError("Dissection does not contain the device descriptor. Filter less stuff out.")

    for frame in device_descs:
        desc = frame["DEVICE DESCRIPTOR"]
        if not (int(desc["usb.idVendor"], 0) == ID_VENDOR and int(desc["usb.idProduct"], 0) == ID_PRODUCT):
            continue
        usb = frame["usb"]
        return int(usb["usb.bus_id"], 0), int(usb["usb.device_address"], 0)

    raise ValueError("Dissection does not contain the device descriptor. Filter less stuff out.")


def filter_device_frames(j: list, bus: int, dev: int) -> typing.Iterable:
    for i in jq.all(fr'map(._source.layers) | map(select((.usb."usb.dst" | test("{bus}\\.{dev}\\.\\d")) or '
                    fr'(.usb."usb.src" | test("{bus}\\.{dev}\\.\\d")))) | .[]', j):
        if int(i["usb"]["usb.transfer_type"], 0) != 3:  # URB_BULK
            continue
        yield i


def check_malformed(j: list) -> bool:
    return jq.one('map(._source.layers) | map(has("_ws.malformed")) | any', j)


def print_frame(frame: dict) -> None:
    time = float(frame["frame"]["frame.time_relative"])
    direction = "→" if frame["usb"]["usb.src"] == "host" else "←"
    ep_dir = "IN" if int(frame["usb"]["usb.endpoint_address_tree"]["usb.endpoint_address.direction"], 0) == 1 else "OUT"
    ep_num = int(frame["usb"]["usb.endpoint_address_tree"]["usb.endpoint_address.number"], 0)
    length = int(frame["usb"]["usb.data_len"], 0)
    data = frame.get("usb.capdata", "").split(":")
    color = Colors.LIGHT_GREEN if ep_dir == "OUT" else Colors.LIGHT_PURPLE

    data_str = ""
    data_line_len = 0
    header_len = 22  # lol
    width = os.get_terminal_size().columns
    for byte in data:
        data_str += byte
        data_line_len += 2
        if data_line_len + 3 + header_len > width:
            data_str += "\n" + " " * header_len
            data_line_len = 0
        else:
            data_str += " "
            data_line_len += 1
    data_str = data_str[:-1]

    print(f"{color}{time:>7.2f} {direction} {ep_dir:<3} {ep_num}  [{length:>2}] {data_str}{Colors.END}")


def main(fname: str):
    with open(fname) as f:
        j = json.load(f)

    if check_malformed(j):
        warnings.warn("Dissection has malformed packets!")
        print("Dissection has malformed packets!")
        print("To be able to parse the dissection you need to disable the bitchy dissector by going into 'Analyze' > "
              "'Enabled Protocols...'.\nIt is usually IPPUSB.")

    bus, dev = find_bus_device(j)
    frames = filter_device_frames(j, bus, dev)

    for frame in frames:
        print_frame(frame)


if __name__ == '__main__':
    try:
        _fname = sys.argv[1]
        main(_fname)
    except IndexError:
        print(f"Usage: {sys.argv[0]} [dissected.json]")
        exit(1)
