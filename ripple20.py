#!/usr/bin/python
# -*- coding: UTF-8 -*-
from scapy.all import *
import sys
ICMP_MS_SYNC_REQ_TYPE = 0xa5
ICMP_MS_SYNC_RSP_TYPE = 0xa6
print("***************************************************")
print("** Treck Network Stack Discovery Tool by JSOF    **")
print("** Version: 1.0                                  **")
print("** Release: 06/30/2020                           **")
print("** By: Jiansiting                                **")
print("***************************************************")
print(" ")
if len(sys.argv)<2 :
    print("[*] Lost IP Address!")
else:
    ip=sys.argv[1]
    q = IP(dst=ip)/ICMP()
    ans1, unans1 = sr(q, timeout=1)
    if not ans1:
        print("[!] The target is not alive!")
        exit(0)
    else:
        print("[*] The target is alive!")
    p = IP(dst=ip)/ICMP(type=ICMP_MS_SYNC_REQ_TYPE,code=0)
    ans, unans = sr(p, timeout=1)
    if not ans:
        print("[*] The target is not respond for the active test")         
    for req, resp in ans:
        if ICMP in resp and resp[ICMP].type == ICMP_MS_SYNC_RSP_TYPE:
            print("[!] The target does contain network stack of treck")  
        else:
            print("[*] The target does not contain network stack of treck")  