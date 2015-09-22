#!/usr/bin/env python

import os
import threading
import socket
import time
import wccplib as wlib
from optparse import OptionParser

g_app_exiting = False
g_wccp_server_list = []
g_current_ip = ""
g_logfile_handle = None

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
        print("[*] IPs not formatted correctly")
        raise ValueError

    return (None,None)

def listener(sock):
    global g_wccp_server_list
    global g_app_exiting
    
    print("[*] Starting listener...") 
    while not g_app_exiting:
        try:
            data, addr = sock.recvfrom(1024)
            if data:
                host, port = addr
                g_wccp_server_list.append(addr)
                print("[*] Received a hit from " + host)

                if g_logfile_handle != None:
                    g_logfile_handle.write(host + "\n")

        except KeyboardInterrupt:
            print("\x08\x08[*] Exiting...")
            sock.close()
            exit(0)
def reporter():
    global g_app_exiting
    global g_current_ip

    while not g_app_exiting:
        data = raw_input("")
        print("[*] Current IP %s" % g_current_ip)
        time.sleep(1)
def show_stats():
    if len(g_wccp_server_list) == 0:
        print("[*] Nothing found!")
    else:
        print("[-] Found %d WCCP servers" % len(g_wccp_server_list))
        for entry in g_wccp_server_list:
            host,port = entry
            print(host)

        
def main():
    global g_app_exiting
    global g_wccp_server_list
    global g_current_ip
    global g_logfile_handle

    parser = OptionParser()
    parser.add_option("-t", "--target", dest="hostrange", help="IP range: x.x.x.x-y.y.y.y")
    parser.add_option("-s", "--server", dest="serveraddr", help="WCCP Server IP (disables NAT punch-through)")
    parser.add_option("-o", "--output", dest="outputfile", help="Log file")


    (options, args) = parser.parse_args()
    
    if not options.hostrange:
        print "Supply a host range with -t"
	return -1
    
    if not options.serveraddr:
        wan_ip = wlib.get_my_wan_address()
        print("[*] External WAN address %s" % wan_ip)
    else:
        wan_ip = options.serveraddr
        print("[*] Using manual server address %s" % wan_ip)

    if options.outputfile:
        g_logfile_handle = open(options.outputfile, "w")
    

    HOST_PORT = 2048

    start, stop = get_ips_from_host(options.hostrange)

    print("[*] Starting address %s\n[*] Stopping address %s" % (start, stop))

    startObj = wlib.ip_address(start)
    stopObj = wlib.ip_address(stop)
    
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('',HOST_PORT))

    t = threading.Thread(target=listener, args={sock,})
    t.setDaemon(True)
    t.start()

    r = threading.Thread(target=reporter)
    r.setDaemon(True)
    r.start()

    print("[*] Running scan...")
    try:
        for ip in ip_generator(startObj, stopObj):
            if ip.bytes2string() == None:
                continue
            message = wlib.wccp_message(ip,wan_ip)
            message = message.get_message()

            g_current_ip = ip.bytes2string()

            sock.sendto(message, (g_current_ip,HOST_PORT))
            time.sleep(0.0001)

    except KeyboardInterrupt:
        print("\x08\x08[*] Exiting...")
        show_stats()
        sock.close()
        exit(0)

    print("[*] Sending complete...")

    print("[*] Waiting 2 seconds for any delayed responses...")
    time.sleep(2)

    print("[*] Wrapping things up...")

    show_stats()

    g_app_exiting = True

    return 0

if __name__=="__main__":
	ret = main()
        exit(0)
