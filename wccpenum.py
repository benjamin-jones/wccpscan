#!/usr/bin/env python3

import socket
import struct
import wccplib as wlib
from optparse import OptionParser

def process_response(data):
    try:
        isy = wlib.wccp_isy_message(data)
        sid = isy.service_id
        return "%d - VALID SERVICE ID!!!!" % sid
    except:
        return None

def show_stats(result_list):
    for entry in result_list:
        if entry:
            print(entry)

def service_scan(target, srvip, start=None):
    if start:
        begin = int(start)
    else:
        begin = 0
    for i in range(begin,256):
        print("[*] Trying service_id=%d" % i)
        yield wlib.wccp_hia_message(target, srvip, None, struct.pack("!B", i)), i
        
def main():
    parser = OptionParser()
    parser.add_option("-t", "--target", dest="target", help="IP range: x.x.x.x-y.y.y.y")
    parser.add_option("-s", "--server", dest="serveraddr", help="WCCP Server IP (disables NAT punch-through)")
    parser.add_option("-i", "--start-id", dest="s_id", help="WCCP Service ID starting value")

    (options, args) = parser.parse_args()

    if not options.target:
        print("[*] Supply a target with -t")
        return -1
    
    if not options.serveraddr:
        wan_ip = wlib.get_my_wan_address()
        print("[*] External WAN address %s" % wan_ip)
    else:
        wan_ip = options.serveraddr
        print("[*] Using manual server address %s" % wan_ip)

    HOST_PORT = 2048


    target = wlib.ip_address(options.target)
    srvip = wlib.ip_address(options.serveraddr)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', HOST_PORT))

    print("[*] Running scan...")
    service_info = []
    current_ip = target.bytes2string()
    mip = srvip.bytes2string()
    try:
        for message, sid in service_scan(target, mip, options.s_id):
            message = message.get_message()
            sock.sendto(message, (current_ip,HOST_PORT))
            try:
                data, _ = sock.recvfrom(1024)
                service_info.append(process_response(data))
            except socket.timeout:
                continue

    except KeyboardInterrupt:
        print("\x08\x08[*] Exiting...")
        pass
    
    sock.close()

    print("[*] Sending complete...")

    show_stats(service_info)

    return 0


if __name__ == "__main__":
    ret = main()
    exit(0)
