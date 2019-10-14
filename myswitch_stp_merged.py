'''
Ethernet learning switch in Python.
Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *

class tableEntry:
    port = -1 
    addr = -1
    ttl = 0

    def __init__(self, port, addr, ttl = 0):
        self.port = port
        self.addr = addr

    def incrementTTL(self):
        self.ttl += 1

def main(net):
    BROADCAST = "ff:ff:ff:ff:ff:ff"
    size = 0
    table = []
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    matched = False
    'Create packet on startup to be sent every x seconds'
    timer = 1
    spm = SpanningTreeMessage("ID", hops_to_root=1)
    idCurrentRoot = Self
    hopsToRoot = 0
    receivedSpanningTreeIntf = 'interface spanningtreepacket was received'
    timeSTPReceived = 0

    'Interface that leads to the root'
    interface = 'null for now'
    'I think switch MAC Ethaddr is in the interface so do not need an additional variable to store that'

    while True:
        try:
            recInfo = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        print("Current Packet: {}".format(net.name))

        ethernet = recInfo.packet.get_header(Ethernet)
        if ethernet is None:
            print("Received a non-Ethernet packet?!")
            continue

        if ethernet.dst in mymacs:
            print ("Received a packet intended for me")
            continue

        #handle broadcasting
        if ethernet.dst == BROADCAST:
            broadcast(net, recInfo)

        else:
            #loop through table
            for entry in table:
                if entry.addr == ethernet.dst:
                    print("Matched in my table! ")
                    net.send_packet(entry.port, recInfo.packet)
                    matched = True

                else:
                    insertEntry(recInfo.port, ethernet.dst, size, table)
                    log_info("Added a new table entry. ")
                    broadcast(net, recInfo)

            if matched == False:
                broadcast(net, recInfo)

        matched = False

    'Only initialize STP protocol if thinks self is root node, do not know how to repeat this every timer seconds'
    if idCurrentRoot = self:
    	'Building packet'
    	Ethernet.add_next_header_class(EtherType.SLOW, SpanningTreeMessage)
    	pkt = Ethernet(src="ID",dst="ID",ethertype=EtherType.SLOW) + spm
	
    'Check current time'
    if currentTime > timeSTPReceived + 30:
	idCurrentRoot = self
	'Send out packets every timer seconds'

    'I do not know if we need to check the size of the packet to ensure > 40 bytes'
    'Send out built packet along all Ports every timer seconds, do not know the code for this'

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        ethernet = packet.get_header(Ethernet)

        'If header contains the spanning tree packet'
        
	    if packet[SpanningTreeMessage].root 'ID portion of the header I think' != null:
	        timeSTPReceived = recv_packet.timestamp
	        if packet[SpanningTreeMessage].root < idCurrentRoot:
		        idCurrentRoot = packet[SpanningTreeMessage].root
		        packet[SpanningTreeMessage].hops_to_root = packet[SpanningTreeMessage].hops_to_root + 1
		        hopsToRoot = packet[SpanningTreeMessage].hops_to_root + 1
		        interface = input_port
		    for intf in my_interfaces:
                if input_port != intf.name:
                   	log_debug ("Flooding packet {} to {}".format(packet, intf.name))
		    	    net.send_packet 'send packet out if the interface was not the one received'
	        elif packet[SpanningTreeMessage].root = idCurrentRoot:
		        if packet[SpanningTreeMessage].hops_to_root + 1 < hopsToRoot:
		            interface = input_port
		            packet[SpanningTreeMessage].hops_to_root = packet[SpanningTreeMessage].hops_to_root + 1
		            hopsToRoot = packet[SpanningTreeMessage].hops_to_root + 1
		                for intf in my_interfaces:
                    	    if input_port != intf.name:
                    	    log_debug ("Flooding packet {} to {}".format(packet, intf.name))
		    	    net.send_packet 'send packet out if the interface was not the one received'
	    else:
            if packet[0].dst in mymacs:
                log_debug ("Packet intended for me")
                continue
            
            if ethernet.dst == BROADCAST
                broadcast(net, input_port, packet)
                continue

            #loop through table
            for entry in table:
                if entry.addr == ethernet.dst:
                    net.send_packet(entry.port, packet)
                    matched = True

                else:
                    insertEntry(port, ethernet.dst, size, table)
                    broadcast(net, input_port, packet)

            if matched == False:
                broadcast(net, input_port, packet)

        matched = False

    net.shutdown()

def broadcast(net, input_port, packet):
    for port in net.ports():
        if port.name != input_port:
            net.send_packet(port.name, packet)

def insertEntry(port, addr, size, table):
        #CHECK FOR DUPLICATE ENTRIES AND DELETE OLD ONE
        entry = tableEntry(port, addr)
        if(size == 5):
            table.pop(4)
        else:
            size += 1

        table.insert(0, entry)

        for x in table:
            x.incrementTTL()
