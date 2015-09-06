#!/usr/bin/env python

import os
import threading
import socket
import time
import wccplib as wlib
from optparse import OptionParser

def ip_generator(start, stop):
    
    current = start
    while current <= stop:
        yield current
        current = current.next()

def get_ips_from_host(ip):

    ip_list = ip.split("-")

    if len(ip_list) == 2:
        return ip_list[0], ip_list[1]
    else:
        print("IPs not formatted correctly")
        raise ValueError

    return (None,None)

def listener(sock):
    print("Starting listener...") 
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if data:
                print("Received a hit from %s" % addr)
        except KeyboardInterrupt:
            sock.close()
            exit(0)
        time.sleep(0.1)
        
def main():
    parser = OptionParser()
    parser.add_option("-t", "--target", dest="host", help="Target IP range")
    parser.add_option("-q", "--quiet", action="store_false", dest="verbose", default=True, help="Don't print status messages")

    (options, args) = parser.parse_args()
    
    if not options.host:
        print "Supply a host with -t"
	return -1
    
    wan_ip = wlib.get_my_wan_address()
    
    print("External WAN address %s" % wan_ip)

    HOST_PORT = 2048

    start, stop = get_ips_from_host(options.host)

    print("Starting address %s\nStopping address %s" % (start, stop))

    startObj = wlib.ip_address(start)
    stopObj = wlib.ip_address(stop)
    
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('',HOST_PORT))

    t = threading.Thread(target=listener, args={sock,})
    t.setDaemon(True)
    t.start()

    print("Running scan...")
    try:
        for ip in ip_generator(startObj, stopObj):
            if ip.bytes2string() == None:
                continue
            message = wlib.wccp_message(ip,wan_ip)
            message = message.get_message()

            UDP_IP = ip.bytes2string()

            sock.sendto(message, (UDP_IP,HOST_PORT))
            time.sleep(0.1)
    except KeyboardInterrupt:
        sock.close()
        exit(0)

    print("Sending complete...")

    t.join()

    return 0

if __name__=="__main__":
	ret = main()
