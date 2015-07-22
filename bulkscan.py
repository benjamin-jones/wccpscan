#!/usr/bin/env python

import sys
import subprocess
from threading import Thread

def scan_ip(ip, rip):
        print(subprocess.check_output("./wccpscan.py -m " + rip + " -t " + ip + "; exit 0",
              stderr=subprocess.STDOUT,
              shell=True).strip())


def get_wan_addr():
    wanip = subprocess.check_output(["./wccpscan.py",""])
    print("Got WAN IP: " + wanip)

    return wanip.strip()

def ipRange(start_ip, end_ip):
   start = list(map(int, start_ip.split(".")))
   end = list(map(int, end_ip.split(".")))
   temp = start
   ip_range = []
   
   ip_range.append(start_ip)
   while temp != end:
      start[3] += 1
      for i in (3, 2, 1):
         if temp[i] == 256:
            temp[i] = 0
            temp[i-1] += 1
      ip_range.append(".".join(map(str, temp)))    
      
   return ip_range
   
def main():   
    
    args = sys.argv

    if len(args) != 3:
        print("Usage: ./bulkscan.py [start ip] [stop ip]")
        exit(-1)

    args = args[1:]

    startip = args[0]
    stopip = args[1]
    
    ip_range = ipRange(startip, stopip)


    rip = get_wan_addr()

    for ip in ip_range:
        t = Thread(target=scan_ip, args=(ip,rip,))
        t.start()

if __name__=="__main__":
    main()
