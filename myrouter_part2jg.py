
#!/usr/bin/env python3
'''
Basic IPv4 router (static routing) in Python.
'''
import sys
import os
import time
from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *
from switchyard.lib.address import *
import pdb
import ipaddress

class ForwardingEntry(object):
    def __init__(self, prefix, mask, portName, nextHopAddr = None):
        self.prefix = prefix
        print("forwarding Entry")
        print(self.prefix)
        self.mask = mask
        print(self.mask)
        self.nexthop = nextHopAddr
        self.portName = portName

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        self.arp_table = {} #first initialize empty ARP table for IP-MAC pairs
        self.my_interfaces = net.interfaces()
        self.fTable = {}
        print(self.fTable)
        self.populateForwardingTable()
        print("printing my table's contents:")
        for x in self.fTable:
            print(x)
            print(self.fTable[x].portName)
            print(type(self.fTable[x].prefix))
            print(self.fTable[x].mask)
            print(type(self.fTable[x].mask))
            print()

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

            print(pkt)

            if pkt.has_header(Arp):
                ARPMatched = False
                arpPkt = pkt[Arp]
                for interface in self.my_interfaces:
                    if interface.ipaddr == arpPkt.targetprotoaddr:
                        ARPMatched = True
                        break

                if ARPMatched == True:
                    #store in ARP table
                    self.arp_table[arpPkt.senderprotoaddr] = arpPkt.senderhwaddr
                    #send ARP reply
                    targetEth = arpPkt.senderhwaddr
                    targetIP = arpPkt.senderprotoaddr
                    sourceIP = arpPkt.targetprotoaddr
                    sourceEth = interface.ethaddr
                    arpReply = create_ip_arp_reply(sourceEth,targetEth,sourceIP,targetIP)
                    self.net.send_packet(input_port,arpReply)

            if pkt.has_header(IPv4):
                IPMatched = False
                ipPkt = pkt[IPv4]
                print("Check Match")
                print(ipPkt)
                match = self.checkMatch(ipPkt)
                print("Matched! {}".format(match))
                if match != 0:
                    print("test")
                    ipPkt.ttl = ipPkt.ttl - 1 #decrement TTL
                    eth = Ethernet()
                    print(self.fTable[match])
                    print(self.fTable[match].nexthop)
                    #pdb.set_trace()
                    eth.dst = pkt[Ethernet].src
                    eth.ethertype = EtherType.IP
                    p = Packet()
                    p += eth
                    p += ipPkt
                    self.net.send_packet(self.fTable[match].portName,p)


    def checkMatch(self, ipPkt):
        #netaddr = IPv4Network(ipPkt.prefix + "/" + ipPkt.mask)
        destAddr = IPv4Address(ipPkt.dst)
        matchedEntry = False        
        matchedLength = 1
        matchedIP = 0
        count = 0
        for entry in self.fTable:
            count = count + 1
            print(count)
            tableObj = self.fTable[entry]
            mask = IPv4Address(tableObj.mask)
            netPrefix = IPv4Network(tableObj.prefix).network_address
            print("Mask {}, netPrefix {}, destAddr {}".format(mask,netPrefix,destAddr))
            if (int(mask) & int(destAddr)) == int(netPrefix):
                print("In if matched...")
                print("Table's ip prefix: ")
                print(netPrefix)
                print("packet's destination: ")
                print(destAddr)
                print("Table's port name: ")
                print(self.fTable[entry].portName)
                matchedEntry = True
                print(tableObj.prefix)
                netAddr = IPv4Network(tableObj.prefix)
                newLength = netAddr.prefixlen
                print("New Length: ")
                print(newLength)
                print(matchedLength)
                if newLength > matchedLength:
                    matchedLength = newLength
                    matchedIP = tableObj.prefix
            print(matchedIP)
        return matchedIP

    def populateForwardingTable(self):
        #net interfaces
        for intf in self.my_interfaces:
            #self.fTable[str(intf.ipaddr)] = ForwardingEntry(str(intf.ipaddr), str(intf.netmask), intf.name)
            pxMain = str(intf.ipaddr) + "/" + str(intf.netmask)
            self.fTable[ipaddress.IPv4Interface(pxMain).network] = ForwardingEntry(ipaddress.IPv4Interface(pxMain).network, intf.netmask, intf.name)
        print(self.fTable)
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
                line = line.strip("\n")
                data = line.split(" ")
                #self.fTable[data[0]] = ForwardingEntry(data[0], data[1], data[3], data[2])
                #pdb.set_trace()
                prefixMain = data[0]+"/"+data[1]
                self.fTable[IPv4Network(prefixMain)] = ForwardingEntry(IPv4Network(prefixMain), data[1], data[3], data[2])
                print("data0: {} data1: {} data2: {} data3: {}".format(data[0],data[1],data[2],data[3]))
                print(self.fTable[IPv4Network(prefixMain)])

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
