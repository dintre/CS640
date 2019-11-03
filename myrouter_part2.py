
#!/usr/bin/env python3
'''
Basic IPv4 router (static routing) in Python.
'''
import sys
import os
import time
from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *

class ForwardingEntry(object):
    def __init__(self, prefix, mask, portName, nextHopAddr = None):
        self.prefix = prefix
        self.mask = mask
        self.nexthop = nextHopAddr
        self.portName = portName

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        self.arp_table = {} #first initialize empty ARP table for IP-MAC pairs
        self.my_interfaces = net.interfaces()
        self.fTable = {}
        self.populateForwardingTable()
        for x in self.fTable:
            print(x.portName)
    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                timestamp,input_port,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break
            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))

            if pkt.has_header(Arp):
                matched = False
                arpPkt = pkt[Arp]
                for interface in self.my_interfaces:
                    if interface.ipaddr == arpPkt.targetprotoaddr:
                        matched = True
                        break

                if matched == True:
                    #store in ARP table
                    self.arp_table[arpPkt.senderprotoaddr] = arpPkt.senderhwaddr
                    #send ARP reply
                    targetEth = arpPkt.senderhwaddr
                    targetIP = arpPkt.senderprotoaddr
                    sourceIP = arpPkt.targetprotoaddr
                    sourceEth = interface.ethaddr
                    arpReply = create_ip_arp_reply(sourceEth,targetEth,sourceIP,targetIP)
                    self.net.send_packet(input_port,arpReply)

    def populateForwardingTable(self):
        #net interfaces
        for intf in self.my_interfaces:
            self.fTable[intf.ipaddr] = ForwardingEntry(intf.ipaddr, intf.netmask, intf.name)

        #read from file
        '''172.16.0.0 255.255.0.0 192.168.1.2 router-eth0
        172.16.128.0 255.255.192.0 10.10.0.254 router-eth1
        172.16.64.0 255.255.192.0 10.10.1.254 router-eth1
        10.100.0.0 255.255.0.0 172.16.42.2 router-eth2'''
        file = open("forwarding_table.txt", "r")
        if file.mode == 'r':
            fileData = file.readlines()
            print("Reading entries into table...")
            for line in fileData:
                data = line.split(" ")
                self.fTable[data[0]] = ForwardingEntry(data[0], data[1], data[3], data[2])

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()

