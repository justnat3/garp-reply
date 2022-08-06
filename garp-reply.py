#!/usr/bin/env python3
# \author   Nathan Reed <nreed@linux.com>
#
# \desc     sending garp replys(opcode 1) during a failure over in response to an issue with meraki
#           meraki itself does not accept garp requests (opcode 0)
#
# \title garp-reply.py
#
# Assumes knowledge of
# - keepalived.conf - https://manpages.debian.org/unstable/keepalived/keepalived.conf.5.en.html
#
# low-level packet interface
# - packet(7) - https://man7.org/linux/man-pages/man7/packet.7.html
#
# low-level socket interface
# - socket(2) - https://man7.org/linux/man-pages/man2/socket.2.html
# - socket(7) - https://man7.org/linux/man-pages/man7/socket.7.html


from dataclasses import dataclass, field
from subprocess import run, PIPE
from struct import pack
from socket import (
    inet_aton,
    socket,
    SOCK_RAW,
    SOCK_DGRAM,
    AF_INET,
    # not supported on windows
    AF_PACKET,  # pyright: ignore
)
import os


# What is GARP?
# Gratuitous ARP is meant to provide a way to resolve ARP table conflicts

# Packet payload
# HTYPE2B->PTYPE2B->HLEN1B->PSIZE1B->OPCODE2B->SHA6B->SPA4B->THA6B->TPA4B
# HA  - MAC
# PA  - IP
# LEN - LENGTH


# offset is in bits
#                   OFFSET
# 0                                       15
# +---------------------------------------+
# |                 HTYPE                 |
# +---------------------------------------+
# |                 PTYPE                 |
# +---------------------------------------+
# |       HLEN        |         PLEN      |
# +---------------------------------------+
# |                 OPCODE                |
# +---------------------------------------+
# |                  SHA                  |
# |                  SHA                  |
# |                  SHA                  |
# +---------------------------------------+
# |                  SPA                  |
# |                  SPA                  |
# +---------------------------------------+
# |                  THA                  |
# |                  THA                  |
# |                  THA                  |
# +---------------------------------------+
# |                  TPA                  |
# |                  TPA                  |
# +---------------------------------------+


# ip shell str lengths # kinda yikes
inet_len = 4
brd_len = 3

# custom base mac
VMAC_BASE = bytearray(b"\x00\x00\x5E\x00\x01")

# Generic MACS
BMAC = pack("!6B", *(0xFF,) * 6)
ZMAC = pack("!6B", *(0x00,) * 6)

# headers
OP_CODE = pack("!H", 0x0002)
HTYPE = 0x0001
PTYPE = 0x0800
HLEN = 0x0006
PLEN = 0x0004

ARP_ETHERNET_HEADER = pack("!HHBB", HTYPE, PTYPE, HLEN, PLEN)
ETHTYPE_ARP = pack("!H", 0x0806)

# predictable interface names
SYSFS_INTERFACES = "/sys/class/net/"
INTERFACES = ["ens160", "eth0"]
AVG_IP_START = None

def main() -> int:
    print("[INFO]   Parsing VRRP Config")
    
    _, host_addr = grab_host_address()
    
    # WARNING: this is assuming that your virtual_ip is in the same scheme as your interface IP
    AVG_IP_START = "".join(host_addr.split(".")[:3])
    
    # parse the keepalive configuration
    config = ConfigParser("/etc/keepalived/keepalived.conf")
    config = config.parse_config()

    VMAC_BASE.append(config["virtual_router_id"])
    vmac_haddr = bytes(VMAC_BASE)

    vmac_addr = bytes(config["virtual_ip"])
    
    print("[INFO]   Crafting GARP Packet")
    packet = create_garp_reply(vmac_haddr, vmac_addr)
    
    print("[INFO]   Sending GARP Packet")
    send_garp_reply(packet)

    print("[INFO]   Done!")
    return 0


@dataclass
class ConfigParser(object):
    f_path: str
    cursor: int = field(init=False)
    lookahead: int = field(init=False)
    f_chars: str = field(init=False)

    def __post_init__(self):
        self.cursor = 0
        self.lookahead = 0
        
        assert os.path.exists(self.f_path), "config path does not exist"
        
        with open(self.f_path, "r") as f:
            self.f_chars = f.read()
        
        assert self.f_chars.split("\n")

    def check_bounds(self, idx) -> bool:
        return idx >= len(self.f_chars)

    def parse_config(self):
        config = {}

        assert self.f_chars, "no chars"
        assert len(self.f_chars) > 3, "No File"

        chars = self.f_chars.split("\n")

        for option in chars:
            # strip leading spaces
            option = option.strip(" ")

            # grab the virtual router id
            if option.__contains__("virtual_router_id"):
                option = option.split(" ")

                # grab virtual_router definition and convert the 80 to hex
                key = option[0]
                value = int(option[-1])
                config[key] = value

            # grab the virtual router id
            if option.__contains__(AVG_IP_START):
                # option = option.split(" ")

                # grab virtual_router definition and convert the 80 to hex
                key = "virtual_ip"
                value = pack_address(option[0])
                config[key] = value

        assert len(config) > 0, "Found no configuration options"
        return config

        # unreachable
        assert False, "end of scope too early"


def pack_address(address: str) -> bytes:
    # validate ip addr
    assert len(address) > 5, f"invalid length for addres {address}"
    assert inet_aton(address), f"Invalid Address {address}"

    # split the address off into decimal byte segments
    octets = address.split(".")

    # take all the decimal segments and pack them all into a 4 byte struct
    packed = pack("!4B", *[int(octet) for octet in octets])

    return packed


def get_interface_name() -> str:
    interface_name = None
    interfaces = os.listdir(SYSFS_INTERFACES)

    for interface in interfaces:
        if interface in INTERFACES:
            interface_name = interface

    assert interface_name, f"interface is {type(interface_name)}"
    assert isinstance(interface_name, str), f"Interface is not str {interface_name}"

    return interface_name


def grab_host_address():
    interface_name = get_interface_name()

    assert isinstance(interface_name, str), "interface is not a string"

    # grab the interfaces address
    ip = run(
        "ip " + "address " + "show " + interface_name,
        stdout=PIPE,
        shell=True,
        stderr=PIPE,
    )

    # bundle stderr and assert for better error reporting
    err = ip.stderr.decode("utf-8")
    assert ip.returncode == 0, f"ip exited uncleanly {ip.returncode, err}"

    # grab the stdout
    ip = ip.stdout.decode("utf-8")

    # get the third line
    address = ip.split("\n")[2]

    inet = address.index("inet")
    brd = address.index("brd")

    assert isinstance(inet, int)
    assert isinstance(brd, int)

    # grab the address
    address = address[inet + inet_len : brd - brd_len - 1].strip(" ")

    return (interface_name, address)


def create_garp_reply(vmac: bytes, vmac_addr) -> bytes:
    assert isinstance(BMAC, bytes), ""
    assert isinstance(ARP_ETHERNET_HEADER, bytes), ""
    assert isinstance(OP_CODE, bytes), ""
    assert isinstance(vmac, bytes), ""
    assert isinstance(vmac_addr, bytes), ""
    assert isinstance(ZMAC, bytes), ""

    # HTYPE2B->PTYPE2B->HLEN1B->PSIZE1B->OPCODE2B->SHA6B->SPA4B->THA6B->TPA4B
    packet = [
        BMAC,
        vmac,
        ETHTYPE_ARP,
        ARP_ETHERNET_HEADER,
        OP_CODE,
        vmac,
        vmac_addr,
        ZMAC,
        vmac_addr,
    ]

    raw_packet = b"".join(packet)
    return raw_packet


def send_garp_reply(raw_packet: bytes) -> int:

    try:
        name, _ = grab_host_address()
        sock = socket(AF_PACKET, SOCK_RAW, SOCK_RAW)
        sock.bind((name, SOCK_RAW))
        sock.send(raw_packet)

    except Exception as err:
        raise Exception(f"bad stuff happened {err}")

    return 0


if __name__ == "__main__":
    main()
