
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

#bufferEntries are packets waiting for an ARP reply
#to an destination that's already been requested
class BufferEntry(object):
    def __init__(self,packet,next):
        self.packet = packet
        self.nexthop = next

#Queue objects hold data about ARP packets that have been requested
#and are being waited on
class QueueEntry(object):
    def __init__(self, timeARPSent, packet, arpPkt, outputPort, next):
        self.tries = 1
        self.timeARPSent = timeARPSent
        self.packet = packet
        self.arpPkt = arpPkt
        self.outputPort = outputPort
        self.nexthop = next

#Object for an entry in the forwarding table of the router
class ForwardingEntry(object):
    def __init__(self, prefix, mask, portName, nextHopAddr = None):
        self.prefix = prefix
        self.mask = mask
        self.nexthop = nextHopAddr
        self.portName = portName

#Object holding data about the router itself
class Router(object):
    #constructor
    def __init__(self, net):
        self.net = net
        self.arp_table = {} #first initialize empty ARP table for IP-MAC pairs
        self.my_interfaces = net.interfaces()
        self.fTable = []
        self.populateForwardingTable()
        self.BROADCAST = "ff:ff:ff:ff:ff:ff"
        self.queue = []
        self.buffer = []

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
                continue
            except Shutdown:
                log_debug("Got shutdown signal")
                break
            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))

            print()
            print(time.time())
            print(pkt)

            #check if this packet is reply we've needed
            if pkt.has_header(Arp):
                arpPkt = pkt[Arp]
                ARPMatched = False
                if arpPkt.operation==ArpOperation.Reply:
                    for q in self.queue:                        
                        if arpPkt.senderprotoaddr == q.packet[IPv4].dst:
                            self.queue.remove(q)
                            for buf in self.buffer:
                                if buf.packet[IPv4].dst == arpPkt.senderprotoaddr:
                                    newpkt = buf.packet
                                    newpkt[IPv4].ttl = newpkt[IPv4].ttl-1
                                    self.net.send_packet(input_port,newpkt)
                            self.buffer.clear()
                            ARPMatched = True
                if ARPMatched == True:
                    #store in ARP table
                    self.arp_table[arpPkt.senderprotoaddr] = arpPkt.senderhwaddr
                    continue

            #check for how long ARP entries have been waiting
            for entry in self.queue:
                #if it's been treid 3 times, drop it and dequeue.
                if entry.tries >= 3:
                    self.queue.remove(entry)
                    #remove related buffer entries
                    self.buffer.clear()
                    
            for entry in self.queue:
                #if it's been 1 second for in-progress request, resend it
                if time.time() - entry.timeARPSent >= 1:
                    entry.tries = entry.tries + 1
                    self.net.send_packet(entry.outputPort,entry.arpPkt)
                    

#-----------Received ARP packet handling--------------------------------------------
            if pkt.has_header(Arp):
                ARPMatched = False
                arpPkt = pkt[Arp]
                doneReply = False

                for interface in self.my_interfaces:
                    if interface.ipaddr == arpPkt.targetprotoaddr:
                        ARPMatched = True
                        break

                if ARPMatched == True:
                    #store in ARP table
                    self.arp_table[arpPkt.senderprotoaddr] = arpPkt.senderhwaddr
                    if doneReply == True:
                        continue

                    #send ARP reply
                    if arpPkt.operation==ArpOperation.Request:
                        targetEth = arpPkt.senderhwaddr
                        targetIP = arpPkt.senderprotoaddr
                        sourceIP = arpPkt.targetprotoaddr
                        sourceEth = interface.ethaddr
                        arpReply = create_ip_arp_reply(sourceEth,targetEth,sourceIP,targetIP)
                        self.net.send_packet(input_port,arpReply)

#-----------IPv4 packet handling--------------------------------------------

            if pkt.has_header(IPv4):
                ipPkt = pkt[IPv4]
                #first look for dest==this router's port ip
                selfMatch = self.checkThisRouter(ipPkt)
                if selfMatch == True:
                    continue

                #look up IP destination address in forwarding table
                matchEntry = self.checkMatch(ipPkt)
                if matchEntry == 0:
                    print("No match in forwarding table; dropping packet.")
                    continue #if nothing in forwarding table, return to top of loop
                
                #check if ARP table already contains this pair
                hasARPAlready = self.checkForAddr(matchEntry)

                #if ARP table does have the pair,
                #send the packet out the correct port
                if hasARPAlready != 0:
                    ipPkt.ttl = ipPkt.ttl - 1
                    outputPort = findPort(hasARPAlready)
                    self.net.send_packet(outputPort,pkt)

                #if ARP table does NOT have the pair,
                #create an ARP request and send it. Also enqueue it.
                if hasARPAlready == 0:
                    bufMatch = 0
                    for buf in self.buffer:
                        if buf.nexthop == matchEntry.nexthop:
                            bufMatch = 1
                    if bufMatch == 1:
                        self.buffer.append(BufferEntry(pkt,matchEntry.nexthop))                    
                        continue
                    srchw = 1
                    for intf in self.net.interfaces():
                        if matchEntry.prefix == str(intf.ipaddr):
                            srchw = intf.ethaddr
                    sendarppkt = create_ip_arp_request(srchw,matchEntry.prefix,ipPkt.dst)
                    self.net.send_packet(matchEntry.portName,sendarppkt)
                    self.queue.append(QueueEntry(time.time(),pkt,sendarppkt,matchEntry.portName,matchEntry.nexthop))
                    self.buffer.append(BufferEntry(pkt,matchEntry.nexthop))



    #Other router methods
    def findPort(self, entry):
        for port in self.my_interfaces:
            if port.ethaddr == entry:
                return port.name
        return 0

    def checkForAddr(self, entry):
        for x in self.arp_table:
            if x == entry.prefix:        
                return self.arp_table[x]
        return 0

    def checkThisRouter(self, ipPkt):
        destAddr = IPv4Address(ipPkt.dst)
        for port in self.my_interfaces:
            if destAddr == port.ipaddr:
                print("Destination is this router's port; dropping packet")
                return True
        return False

    def checkMatch(self, ipPkt):
        destAddr = IPv4Address(ipPkt.dst)      
        matchedLength = 1
        matched = 0 #need to initialize return value 

        for entry in self.fTable:         
            netAddr = IPv4Network(entry.prefix + "/" + entry.mask,strict=False)
            prefixnet = IPv4Network(entry.prefix + "/" + str(netAddr.prefixlen),strict=False)
            destprefix = IPv4Address(destAddr)
            if destprefix in prefixnet:
                newLength = netAddr.prefixlen
                if newLength > matchedLength:
                    matchedLength = newLength
                    matched = entry

        return matched

    def populateForwardingTable(self):
        #net interfaces
        for intf in self.my_interfaces:
            self.fTable.append(ForwardingEntry(str(intf.ipaddr), str(intf.netmask), intf.name))

        try:
            #read from file
            file = open("forwarding_table.txt", "r")
            if file.mode == 'r':
                fileData = file.readlines()
                print("Reading entries into table...")
                for line in fileData:
                    if line.strip():
                        continue
                    line = line.strip("\n")
                    data = line.split(" ")
                    self.fTable.append(ForwardingEntry(data[0], data[1], data[3], data[2]))
        except IOError:
            print("Could not read a file.")

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()

