
from switchyard.lib.userlib import *
import threading

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
    id = 100000000
    anythingAddr = "ef:ef:ef:ef:ef:ef"

    #find lowest port MAC for ID
    for port in net.interfaces():
        #if id > port.ethaddr:
            #id = port.ethaddr

    #at startup of switch, flood out packets on all ports
    # eth = Ethernet()
    # eth.src = anythingAddr
    # eth.dst = BROADCAST
    # spanMessage = SpanningTreeMessage()
    # spanMessage += eth


    #Ethernet.add_next_header_class(EtherType.SLOW, SpanningTreeMessage)
    #pkt = Ethernet(src="ID",dst="ID",ethertype=EtherType.SLOW) + spm
    spm = SpanningTreeMessage("ID", hops_to_root=1)
    eth = Ethernet()
    eth.add_next_header_class(EtherType.SLOW, SpanningTreeMessage)
    pkt = eth(src="ID",dst="ID",ethertype=EtherType.SLOW) + spm
    broadcast(net, pkt)


    while True:
        if idCurrentRoot == self:
    	    Ethernet.add_next_header_class(EtherType.SLOW, SpanningTreeMessage)
    	    pkt = Ethernet(src="ID",dst="ID",ethertype=EtherType.SLOW) + spm

        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        ethernet = packet.get_header(Ethernet)

        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
            continue
            
        if ethernet.dst == BROADCAST:
            broadcast(net, packet, input_port)
            continue

        #loop through table
        for entry in table:
            if entry.addr == ethernet.dst:
                net.send_packet(entry.port, packet)
                matched = True

            else:
                insertEntry(port, ethernet.dst, size, table)
                broadcast(net, packet, input_port)

        if matched == False:
            broadcast(net, packet, input_port)


        matched = False

    net.shutdown()

def broadcast(net, packet, input_port = ""):
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

