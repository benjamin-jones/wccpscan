#
# pyip is a Python package offering assembling/disassembling of raw ip packet
# including ip, udp, and icmp. Also it includes 2 utilities based on raw ip,
# traceroute and ping.
# 
# pyip is released under PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2, and is
# a project inspired by 'ping' written by Jeremy Hylton.
#
# Author: Kenneth Jiang, kenneth.jiang@gmail.com
#


"""Internet packet basic

Simple operations like performing checksums and swapping byte orders.
"""

#from _ip import *
import array
import struct
from socket import htons, ntohs

def ones_complement_16(s, sum=0):
    if len(s) & 1:
        s = s + '\0'

    i = 0
    while i <len(s):
        word = struct.unpack("!H",s[i:i+2])[0]
        sum = sum + word
        i += 2

    hi = sum >> 16
    lo = sum & 0xffff
    sum = hi + lo
    sum = sum + (sum >> 16)

    #while (sum >> 16):
    #    sum = (sum & 0xffff) + (sum >> 16)

    return (sum & 0xffff)

def cksum(s, sum=0):
    sum = ones_complement_16(s, sum)
    return (~sum) & 0xffff

# Should generalize from the *h2net patterns

# This python code is suboptimal because it is based on C code where
# it doesn't cost much to take a raw buffer and treat a section of it
# as a u_short.

# ntohs on Solaris has problem when MSB is set. Replace it with 
# struct 'H' and '!H' format

def __ntohs(s):
    return struct.pack('H', struct.unpack('!H', s)[0])

def __htons(s):
    return struct.pack('!H', struct.unpack('H', s)[0])

def iph2net(s):
    return s[:2] + __htons(s[2:4]) + __htons(s[4:6]) + __htons(s[6:8]) + s[8:]

def net2iph(s):
    return s[:2] + __ntohs(s[2:4]) + __ntohs(s[4:6]) + __ntohs(s[6:8]) + s[8:]

def udph2net(s):
    return __htons(s[0:2]) + __htons(s[2:4]) + __htons(s[4:6]) + s[6:]

def net2updh(s):
    return __ntohs(s[0:2]) + __ntohs(s[2:4]) + __ntohs(s[4:6]) + s[6:]
