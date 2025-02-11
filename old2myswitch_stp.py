from switchyard.lib.userlib import *
import threading
import time
import struct
from SpanningTreeMessage import SpanningTreeMessage
import pdb
Ethernet.add_next_header_class(EtherType.SLOW, SpanningTreeMessage)

class tableEntry:
    port = -1 
    addr = -1

    def __init__(self, port, addr, ttl = 0):
        self.port = port
        self.addr = addr

def lesserId(idOne, idTwo): 
    if str(idOne) < str(idTwo):
        return idOne
    else:
        return idTwo

def createStpPacket(root, hops, switch, hwsrc="20:00:00:00:00:01", hwdst="ff:ff:ff:ff:ff:ff"):
    spm = SpanningTreeMessage(root_id=root, hops_to_root=hops, switch_id=switch)
    pkt = Ethernet(src=hwsrc,
                   dst=hwdst,
                   ethertype=EtherType.SLOW) + spm
    xbytes = pkt.to_bytes()
    p = Packet(raw=xbytes)
    return p

def timeWrapper(function, net, pak, input_port=None):
    def wrapped():
        return function(net, pak, input_port)
    return wrapped
    
def main(net):
    BROADCAST = "ff:ff:ff:ff:ff:ff"
    size = 0
    table = []
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    matched = False
    hops_to_root = 0
    timeLastSPM = 0
    id = ethaddr
    blockedInterfaces = [] #list

    #find lowest port MAC for ID
    for port in net.interfaces():
        if id == None:
            id = port.ethaddr
        else:
            id = lesserId(id, port.ethaddr)
            root_interface = id
            #pdb.set_trace()

    #at startup of switch, flood out packets on all ports
    root_interface = id # a port
    root_switch_id = id # an id is an ethaddr
    pak = createStpPacket(id, 0, id)
    broadcast(net, pak)

    notStarted = True

    while True:
        if root_interface == id:
            if notStarted:
                wrappedFunc = timeWrapper(broadcast, net, pak)
                tFunc = threading.Timer(2.0, wrappedFunc)
                tFunc.start()
                notStarted = False
        else:
            if notStarted == False:
                tFunc.cancel()
                notStarted = True
            if timeLastSPM > timeLastSPM + 10:
                #reset root to self with no blocked interfaces
                root_interface = id
                hops_to_root = 0
                blockedInterfaces = []

        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        ethernet = packet.get_header(Ethernet)

        #spanning tree packet received check
        if packet[SpanningTreeMessage].root != None:
            timeLastSPM = timestamp
            #first examin root's ID. If smaller than current root, check incoming interface with root interface
            if packet[SpanningTreeMessage].root < root_interface:
                #update switch information - step 4
                hops_to_root = packet[SpanningTreeMessage].hops_to_root + 1
                packet[SpanningTreeMessage].hops_to_root = hops_to_root
                root_interface = packet[SpanningTreeMessage].root
                packet[SpanningTreeMessage].switch_id = id
            elif packet[SpanningTreeMessage].switch_id == root_interface:
                #update switch information - step 4
                hops_to_root = packet[SpanningTreeMessage].hops_to_root + 1
                packet[SpanningTreeMessage].hops_to_root = hops_to_root
                root_interface = packet[SpanningTreeMessage].root
                packet[SpanningTreeMessage].switch_id = id
            #otherwise if packet root is greater than current root
            elif packet[SpanningTreeMessage].root > root_interface:
                #remove blocked interface
                for intf in blockedInterfaces:
                    if intf == input_port.name:
                        blockedInterfaces.remove(intf)
            #otherwise if ids match exactly
            elif packet[SpanningTreeMessage].root == root_interface:
                #examine number of hops to root
                if packet[SpanningTreeMessage].hops_to_root + 1 < hops_to_root:
                    #remove blocked interface
                    for intf in blockedInterfaces:
                        if intf == input_port.name:
                            blockedInterfaces.remove(intf)
                    #block original root interface
                    blockedInterfaces.append(root_interface)
                    #update root interface to incoming interface
                    root_interface = input_port
                elif packet[SpanningTreeMessage].hops_to_root + 1 == hops_to_root:
                    if root_switch_id > packet[SpanningTreeMessage].switch_id:
                        #remove blocked interface
                        for intf in blockedInterfaces:
                            if intf == input_port.name:
                                blockedInterfaces.remove(intf)
                        #block original root interface
                        blockedInterfaces.append(root_interface)
                        #update root interface to incoming interface
                        root_interface = input_port
                else:
                    blockedInterfaces.append(root_interface)


        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
            continue
            
        #handle broadcasting
        if ethernet.dst == BROADCAST:
            size = insertEntry(input_port, ethernet.src, size, table)
            broadcast(net, packet, input_port)

        else:
            #loop through table
            for entry in table:
                if entry.addr == ethernet.dst:
                    print("Matched in my table! ")
                    net.send_packet(entry.port, packet)
                    matched = True

            if matched == False:
                size = insertEntry(input_port, ethernet.src, size, table)
                log_info("Added a new table entry. ")
                broadcast(net, packet, input_port)

        matched = False

    net.shutdown()

def broadcast(net, pkt, input_port = None):
    for port in net.ports():
        if port.name != input_port:
            net.send_packet(port.name, pkt)

def insertEntry(port, addr, size, table):
        #CHECK FOR DUPLICATE ENTRIES AND DELETE OLD ONE
        for ent in table:
            if ent.port == port:
                ent.addr = addr
                return size
        entry = tableEntry(port, addr)
        if(size == 5):
            table.pop()
        else:
            size += 1
        table.insert(0, entry)
        return size
