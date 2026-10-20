#!/usr/bin/env python3

# Goal is to use trace a given IP or MAC to it's physical port

# 1 - Get MAC from IP/ARP table
# 2 - Given MAC, inspect mac address table and look for attached port
# 3 - If port connects to another switch, log into that switch and repeat step 2
# 4 - If port connects to end-device, report interface and quit

import ipaddress
import pexpect
import pdb
import sys
import re

user = "removed"
kex = "KexAlgorithms=diffie-hellman-group14-sha1"
mac = False
# 00:50:56:8c:88:6b
linmac_pat = re.compile(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')
mac_pat = re.compile(r'([0-9a-fA-F]{4}\.)+[0-9a-fA-F]{4}')
int_pat = re.compile(r'(Po[0-9]{1,4})(\r)|(Eth[0-9/]{3,})')
phys_int_pat = re.compile(r'(Eth[0-9/]{3,})(\(P\))')
cdp_switch_pat = re.compile(r'([A-Za-z0-9\-\.]{6,})(\([A-Z0-9]{10,}\))')
showint_pat = re.compile(r'(.*) is up')
switch = "removed"
ip = sys.argv[-1]
smiley= '''
                           .......                                             
                    .:--==+++*****+++=-:.                                      
                .:-===++++++++***********+=:                                   
                 .....:--=+++++*+++=--:::::..                                  
                         .:======-.                                            
                     .       ..                  ..                            
                  .*%%+:                       .*%@*-                          
                   =*%#+                        =*%#*.                         
                                                                               
                                                                               
                            .:.                                                
                           .:::.                                               
     .                    :----:.                     =.                       
     -:.                .-=====--:.                 =+*:                       
     ::::.           .:--=========--:.          .:=+***.                       
     :::::::......::--================--------==++***++.                       
     .:::::::------:   :-++++++++++=:.  -=++++++++++++=                        
      .::::--------:     .:-====-:.     -=+++++++++++=-                        
       :::::-----===:.                .-=++++++++++++-                         
       .:::::----=====-:.           :-=++++++++++++++.                         
        .:::::-----======--::::::--==++++++++++++++=-                          
         .:::::-----========================+======:                           
           .:::::-----===========================-.                            
            .::::::------======================-:                              
              .:::::::---------==============-:                                
                                                                               
                                                       
'''




switches = {"removed": "x.x.10.1", "removed": "x.x.10.2",
            "removed": "x.x.10.3", "removed": "x.x.10.4",
            "removed": "x.x.10.5", "removed": "x.x.10.6",
            "removed": "x.x.10.7", "removed": "x.x.10.8",
            "removed": "x.x.10.9", "removed": "x.x.10.10",
            "removed": "x.x.10.11", "removed": "x.x.10.12",
            "removed": "x.x.10.13", "removed": "x.x.10.14",
            "removed": "x.x.10.15", "removed": "x.x.10.16",
            "removed": "x.x.10.17"}

def show_arp(switch, ip):
    pdb.set_trace()
    try:
        if 'some.domain.com' in switch:
            switch = switch.replace('some.domain.com', '')
        nexus_prompt = str(switch + "# ")
        #child = pexpect.spawn("ssh -o HostKeyAlgorithms=+ecdsa -o StrictHostKeyChecking=no -o {} {}@{}".format(kex,user,switches[switch]))
        child = pexpect.spawn("ssh -o HostKeyAlgorithms=+ecdsa -o {} {}@{}".format(kex,user,switches[switch]))
        index = child.expect([nexus_prompt, pexpect.EOF, pexpect.TIMEOUT])
        if index == 0:
            child.sendline("show ip arp {}".format(ip))
            index = child.expect([nexus_prompt, pexpect.EOF, pexpect.TIMEOUT])
            if index == 0:
                try:
                    mac = re.search(mac_pat, child.before.decode('utf-8'))
                    assert(mac)
                    return mac.group(), child
                except AssertionError as e:
                    print("Mac not found for {}. Try pinging it first.".format(ip))
                    child.close()
                    exit()
    except BaseException as e:
        child.close(force=True)

def show_run_int(switch, interface, child):
    if 'some.domain.com' in switch:
        switch = switch.replace('some.domain.com', '')
    nexus_prompt = str(switch + "# ")
    child.sendline("show running-config interface {}".format(interface))
    index = child.expect([nexus_prompt, pexpect.EOF, pexpect.TIMEOUT])
    if index == 0:
        return child.before
    else:
        child.close(force=True)
        exit()

def show_mac(switch, mac, child=None):
    global ip
    try:
        ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError as e:
        ip = "N/A"
        pass
    try:
        if 'some.domain.com' in switch:
            switch = switch.replace('some.domain.com', '')
        nexus_prompt = str(switch + "# ")
        if not child:
            child = pexpect.spawn("ssh -o HostKeyAlgorithms=+ecdsa -o StrictHostKeyChecking=no -o {} {}@{}".format(kex,user,switches[switch]))
            index = child.expect([nexus_prompt, pexpect.EOF, pexpect.TIMEOUT])
            if not index == 0:
                child.close()
                print("Error connecting to switch {}".format(switch))
        # Don't buffer output
        child.sendline("terminal length 0")
        index = child.expect([nexus_prompt, pexpect.EOF, pexpect.TIMEOUT])
        if not index == 0:
            child.close()
            print("Error connecting to switch {}".format(switch))
        child.sendline("show mac address-table address {}".format(mac))
        index = child.expect([nexus_prompt, pexpect.EOF, pexpect.TIMEOUT])
        if index == 0:
            interface = False
            mo = re.search(int_pat, child.before.decode('utf-8'))
            if mo:
                interface = mo.groups()[0]
            # I don't feel like fixing the regex
            if not interface:
                mo = re.search(int_pat, child.before.decode('utf-8'))
                if mo:
                    interface = mo.groups()[2]
            #pdb.set_trace()
            if not interface:
                if 'vPC Peer-Link' in child.before.decode('utf-8').split('\r\n')[-2]:
                    child.sendline("sh vpc statistics peer-link")
                    index = child.expect([nexus_prompt, pexpect.EOF, pexpect.TIMEOUT])
                    if index == 0:
                         mo = re.search(showint_pat, child.before.decode('utf-8'))
                    if mo:
                         interface = mo.groups()[0]
            if 'sup-eth' in child.before.decode('utf-8').split()[-1]:
                print("MAC belongs to {}".format(switch))
                print(smiley)
                child.close()
                return 1
            if 'po' in interface.lower():
                child.sendline("show port-channel summary interface {}".format(interface))
                index = child.expect([nexus_prompt, pexpect.EOF, pexpect.TIMEOUT])
                if index == 0:
                   # Only grabbing first active interface.
                   phys_int = re.search(phys_int_pat, child.before.decode('utf-8')).groups()[0]
                   child.sendline("show cdp neighbors interface {}".format(phys_int))
                   index = child.expect([nexus_prompt, pexpect.EOF, pexpect.TIMEOUT])
                   if index == 0:
                       try:
                           # If no switch detected, consider this host port and print
                           next_switch = re.search(cdp_switch_pat, child.before.decode('utf-8')).groups()[0]
                       except AttributeError as e:
                           iplen = len(str("IP: " + ip))
                           maclen = len(str("MAC: " + mac))
                           switchlen = len(str("SWITCH: " + switch))
                           interfacelen = len(str("INTERFACE: " + interface))
                           physintlen = len(str("PHYS_INT: " + phys_int))
                           bannerlen = max(iplen,maclen,switchlen,interfacelen,physintlen)
                           print("\n")
                           print(str("#" * bannerlen))
                           print("IP: {}\nMAC: {}\nSWITCH: {}\nINTERFACE: {}\nPHYS_INT: {}".format(ip,mac,switch,interface,phys_int))
                           print(str("#" * bannerlen + "\n"))
                           running_int = show_run_int(switch, interface, child)
                           print(running_int.decode())
                           print(smiley)
                           return 0
            elif 'eth' in interface.lower():
                child.sendline("show cdp neighbors interface {}".format(interface))
                index = child.expect([nexus_prompt, pexpect.EOF, pexpect.TIMEOUT])
                if index == 0:
                   try:
                       next_switch = re.search(cdp_switch_pat, child.before.decode('utf-8')).groups()[0]
                   except AttributeError as e:
                       iplen = len(str("IP: " + ip))
                       maclen = len(str("MAC: " + mac))
                       switchlen = len(str("SWITCH: " + switch))
                       interfacelen = len(str("PHYS_INT: " + interface))
                       bannerlen = max(iplen,maclen,switchlen,interfacelen)
                       print("\n")
                       print(str("#" * bannerlen))
                       print("IP: {}\nMAC: {}\nSWITCH: {}\nPHYS_INT: {}".format(ip,mac,switch,interface))
                       print(str("#" * bannerlen + "\n"))
                       running_int = show_run_int(switch, interface, child)
                       #print(running_int.decode())
                       print(smiley)
                       return 0
            print("Tracing MAC {} to Next Switch {}".format(mac,next_switch))
            if "ucs" in next_switch.lower():
                print("UCS switches currently not supported. Exiting...")
                return 0
            child.close()
            child = None
            show_mac(next_switch,mac)
    except AssertionError as e:
        print(e)
        # Temp
        child.close()
    except KeyboardInterrupt as e:
        child.close(force=True)
    except BaseException as e:
        print(e)
        child.close(force=True)
    except AttributeError as e:
        child.close(force=True)

if __name__ == '__main__':
    # Accept only IP or MACs for tracing. IP relies on ARP entry on initial switch.
    try:
        ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError as e:
        try:
            mo = re.search(linmac_pat, ip)
            if not mo:
                mo = re.search(mac_pat, ip)
                if not mo:
                    print("{} is not a valid IP or MAC".format(ip))
                    exit()
                else:
                    mac = mo.group()
            else:
                mac = mo.group()
        except AttributeError as e:
            print("{} is not a valid IP or MAC".format(ip))
            exit()
    try:
        if mac:
            a = show_mac(switch, mac)
        else:
            mac, child_conn = show_arp(switch, ip)
            a = show_mac(switch, mac, child_conn)
    except TypeError as e:
        exit()
    #show_mac(switch, mac, child_conn)
