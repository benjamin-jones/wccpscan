#!/usr/bin/env python3

import struct
import socket
import sys
import inetutils
from pytun import TunTapDevice, IFF_NO_PI, IFF_TUN
from scapy.all import IP as scapyIP
from ip import Packet as ipPacket
from ip import assemble


args = sys.argv[1:]

tun = TunTapDevice(name='wccptun', flags=IFF_NO_PI | IFF_TUN)

print(tun.name)
tun.addr = '192.168.5.3'
tun.netmask = '255.255.255.0'
tun.mtu = 1458

mymac = args[0]
gwmac = args[1]
IPtype = 0x0800

eth_hdr = b"".join([struct.pack("!B",int(i,16)) for i in gwmac.split(":")]) + \
          b"".join([struct.pack("!B",int(i,16)) for i in mymac.split(":")]) + \
          struct.pack("!BB",0x08,00)

gre_hdr = struct.pack("!H", 0x0) + struct.pack("!H", 0x883e) + struct.pack("!I", 0x04000000)

tun.persist(True)

tun.up()

ST = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)
ST3 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)

ST2 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

ST.bind((args[2],0))
ST3.bind(("wccptun",0))

while True:
    buf = tun.read(tun.mtu)
    ip = scapyIP(buf)
    print("[+] recv'd IP src=%s IP dst=%s proto=%s ver=%s" % (ip.src, ip.dst, ip.proto, ip.version))
        
    if (ip.proto == 0x6) and str(ip.src).strip() == str(tun.addr).strip():
            orig_dest = ip.dst
            new_ip = ipPacket(dst=ip.dst, src=args[4], p=0x6, data=buf[20:], ttl=64)
            packet = assemble(new_ip, cksum=1)
            ip = scapyIP(packet)
            del ip['TCP'].chksum
            ip = scapyIP(bytes(ip))
            buf = bytes(ip)
            payload = gre_hdr + buf
            new_ip = ipPacket(dst=args[3], src=args[4], p=47, data=payload, ttl=64)
            packet = assemble(new_ip, cksum=1)
            new_ip = scapyIP(packet)
            print("[+] WCCP GRE return IP src=%s IP dst=%s proto=%s ver=%s" % (new_ip.src, new_ip.dst, new_ip.proto, new_ip.version))
            try:
                ST.send(eth_hdr + bytes(new_ip))
            except OSError:
                print("len = %d" % len(eth_hdr + bytes(new_ip)))
            data, addr = ST2.recvfrom(65535)
            ip = scapyIP(data[14:])
            while str(ip.src).strip() != str(args[3]).strip():
                data, addr = ST2.recvfrom(65535)
                ip = scapyIP(data[14:])
            if (ip.proto == 0x6) and str(ip.src).strip() == str(args[3]).strip():
                new_ip = ipPacket(dst=tun.addr, src=orig_dest, p=0x6, data=ip.payload.build(), ttl=64)
                packet = assemble(new_ip, cksum=1)
                ip = scapyIP(packet)
                del ip['TCP'].chksum
                ip = scapyIP(bytes(ip))
                print("[+] Return packet IP src=%s IP dst=%s proto=%s ver=%s" % (ip.src, ip.dst, ip.proto, ip.version))
                buf = bytes(ip)
                tun.write(buf)
    if (ip.proto == 0x1) and str(ip.src).strip() == str(tun.addr).strip():
            orig_dest = ip.dst
            new_ip = ipPacket(dst=ip.dst, src=args[4], p=0x1, data=buf[20:], ttl=64)
            packet = assemble(new_ip, cksum=1)
            ip = scapyIP(packet)
            buf = bytes(ip)
            payload = gre_hdr + buf
            new_ip = ipPacket(dst=args[3], src=args[4], p=47, data=payload, ttl=64)
            packet = assemble(new_ip, cksum=1)
            new_ip = scapyIP(packet)
            print("[+] WCCP GRE return IP src=%s IP dst=%s proto=%s ver=%s" % (new_ip.src, new_ip.dst, new_ip.proto, new_ip.version))
            try:
                ST.send(eth_hdr + bytes(new_ip))
            except OSError:
                print("len = %d" % len(eth_hdr + bytes(new_ip)))

            data, addr = ST2.recvfrom(65535)
            ip = scapyIP(data[14:])
            while str(ip.src).strip() != str(args[3]).strip():
                data, addr = ST2.recvfrom(65535)
                ip = scapyIP(data[14:])
            if (ip.proto == 0x1) and str(ip.src).strip() == str(args[3]).strip():
                new_ip = ipPacket(dst=tun.addr, src=orig_dest, p=0x1, data=ip.payload.build(), ttl=64)
                packet = assemble(new_ip, cksum=1)
                ip = scapyIP(packet)
                print("[+] Return packet IP src=%s IP dst=%s proto=%s ver=%s" % (ip.src, ip.dst, ip.proto, ip.version))
                buf = bytes(ip)
                tun.write(buf)

        


