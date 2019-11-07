
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

class QueueEntry(object):
    def __init__(self, timeARPSent, packet):
        self.retries = 0
        self.timeARPSent = timeARPSent
        self.packet = packet

class ForwardingEntry(object):
    def __init__(self, prefix, mask, portName, nextHopAddr = None):
        self.prefix = prefix
        self.mask = mask
        self.nexthop = nextHopAddr
        self.portName = portName

class Router(object):
    def __init__(self, net):
        self.net = net
        self.arp_table = {} #first initialize empty ARP table for IP-MAC pairs
        self.my_interfaces = net.interfaces()
        self.fTable = []
        self.populateForwardingTable()
        self.BROADCAST = "ff:ff:ff:ff:ff:ff"
        self.queue = []
        print("printing my table's contents:")
        for x in self.fTable:
            print(x)
            print(x.prefix)
            print(x.mask)
            print(x.portName)
            print(x.nexthop)
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
                    if arpPkt.operation==ArpOperation.Reply:
                        for q in self.queue:
                            if arpPkt.senderprotoaddr == q.packet[IPv4].dst:
                                newpkt = q.packet
                                newpkt[IPv4].ttl = newpkt[IPv4].ttl-1#decrement TTL
                                self.net.send_packet(input_port,newpkt)

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
                #look up IP destination address in forwarding table
                #matchIp = self.checkPortsMatch(ipPkt)
                matchEntry = self.checkMatch(ipPkt)
                print(matchEntry.prefix)
                
                noARP = self.checkForAddr(matchEntry)

                if noARP == 0:
                    srchw = 1
                    for intf in self.net.interfaces():
                        #pdb.set_trace()
                        if matchEntry.prefix == str(intf.ipaddr):
                            srchw = intf.ethaddr

                    #ether = Ethernet()
                    #ether.src = srchw
                    #ether.dst = self.BROADCAST
                    #ether.ethertype = EtherType.ARP
                    #targetmac = ethaddr
                    sendarppkt = create_ip_arp_request(srchw,matchEntry.prefix,ipPkt.dst)
                    self.net.send_packet(matchEntry.portName,sendarppkt)
                    self.queue.append(QueueEntry(1,pkt))
                    #ipPkt.ttl = ipPkt.ttl - 1 #decrement TTL
                    #eth = Ethernet()
                    #eth.dst = pkt[Ethernet].src
                    #eth.ethertype = EtherType.IP
                    #p = Packet()
                    #p += eth
                    #p += ipPkt
                    #self.net.send_packet(matchIp,p)


    def checkForAddr(self, entry):
        for x in self.arp_table:
            if self.arp_table[x] == entry.prefix:
                return self.arp_table[x]
        return 0

    def checkMatch(self, ipPkt):
        destAddr = IPv4Address(ipPkt.dst)      
        matchedLength = 1
        matched = 0 #need to initialize return value 

        for entry in self.fTable:         
            netAddr = IPv4Network(entry.prefix + "/" + entry.mask,strict=False)
            prefixnet = IPv4Network(entry.prefix + "/" + str(netAddr.prefixlen),strict=False)
            #prefixnet = IPv4Network(entry.prefix,strict=False)
            #prefixnet = ipaddress.ip_network(entry.prefix,strict=False)
            destprefix = IPv4Address(destAddr)
            print(prefixnet)
            print(destprefix)
            if destprefix in prefixnet:
                newLength = netAddr.prefixlen
                print("New Length: ")
                print(newLength)
                if newLength > matchedLength:
                    matchedLength = newLength
                    matched = entry

        return matched

    def populateForwardingTable(self):
        #net interfaces
        for intf in self.my_interfaces:
            self.fTable.append(ForwardingEntry(str(intf.ipaddr), str(intf.netmask), intf.name))

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
                self.fTable.append(ForwardingEntry(data[0], data[1], data[3], data[2]))

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()



