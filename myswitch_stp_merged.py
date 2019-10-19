
from switchyard.lib.userlib import *
import threading
import struct
from SpanningTreeMessage import SpanningTreeMessage
import pdb

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

def createStpPacket(self, root_id, hops, switch_id, hwsrc="20:00:00:00:00:01", hwdst="ff:ff:ff:ff:ff:ff"):
    spm = SpanningTreeMessage(root_id=root_id, hops_to_root=hops, switch_id=switch_id)
    Ethernet.add_next_header_class(EtherType.SLOW, SpanningTreeMessage)
    pkt = Ethernet(src=hwsrc,
                   dst=hwdst,
                   ethertype=EtherType.SLOW) + spm
    xbytes = pkt.to_bytes()
    p = Packet(raw=xbytes)
    return p

    
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
    root_switch_id = id # an is is an ethaddr
    pkt = createStpPacket(id, 0, id)
    broadcast(net, pkt)


    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        ethernet = packet.get_header(Ethernet)
        spm = packet.get_header(SpanningTreeMessage)

        #spanning tree packet received check
        if packet[SpanningTreeMessage].root != None:
            timeLastSPM = timestamp
            #first examin root's ID. If smaller than current root, check incoming interface with root interface
            if packet[SpanningTreeMessage].root < root_interface:
                #update switch information - step 4
                hops_to_root = packet[SpanningTreeMessage].hops_to_root + 1
                packet[SpanningTreeMessage].hops_to_root = hops_to_root + 1
                root_interface = packet[SpanningTreeMessage].root
            elif input_port == root_interface:
                #update switch information - step 4
                hops_to_root = packet[SpanningTreeMessage].hops_to_root + 1
                packet[SpanningTreeMessage].hops_to_root = hops_to_root + 1
                root_interface = packet[SpanningTreeMessage].root
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
            net.send_packet(port.name, packet[SpanningTreeMessage])

def insertEntry(port, addr, size, table):
        #CHECK FOR DUPLICATE ENTRIES AND DELETE OLD ONE
        entry = tableEntry(port, addr)
        if(size == 5):
            table.pop(4)
        else:
            size += 1

        table.insert(0, entry)
