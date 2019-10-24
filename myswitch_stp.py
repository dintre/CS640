from switchyard.lib.userlib import *
import threading
import time
import struct
from SpanningTreeMessage import SpanningTreeMessage
import pdb
Ethernet.add_next_header_class(EtherType.SLOW, SpanningTreeMessage) #need this at global level
blockedInterfaces = []

#class to keep track of one individual entry in the FIFO forwarding table
class tableEntry:
    port = -1 
    addr = -1

    def __init__(self, port, addr):
        self.port = port
        self.addr = addr

#returns the smaller id given two addresses
def lesserId(idOne, idTwo): 
    if str(idOne) < str(idTwo):
        return idOne
    else:
        return idTwo

#instantiates a packet with Ethernet and Spanning Tree Message portions
def createStpPacket(root, hops, switch, hwsrc="20:00:00:00:00:01", hwdst="ff:ff:ff:ff:ff:ff"):
    spm = SpanningTreeMessage(root_id=root, hops_to_root=hops, switch_id=switch)
    pkt = Ethernet(src=hwsrc,
                   dst=hwdst,
                   ethertype=EtherType.SLOW) + spm
    xbytes = pkt.to_bytes()
    p = Packet(raw=xbytes)
    return p

#wrapper to hold the broadcast() function
def timeWrapper(function, net, pak, input_port=None):
    def wrapped():
        return function(net, pak, input_port)
    return wrapped

#wrapper to hold the countdown from 10 function
def countWrapper(function, array):
    def wrapped():
        return function(array)
    return wrapped

#after 10.1 seconds, this function is called to set countedDown[0] = True
def countdown(array):
    array[0] = True

#main code entry point
def main(net):
    BROADCAST = "ff:ff:ff:ff:ff:ff"
    size = 0
    table = [] #FIFO forwarding table
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    matched = False
    hops_to_root = 0
    id = ethaddr
    global blockedInterfaces
    countedDown = [False]
    countdownInProgress = False

    #find lowest port MAC for ID
    for port in net.interfaces():
        if id == None:
            id = port.ethaddr
        else:
            id = lesserId(id, port.ethaddr)

    #at startup of switch, flood out packets on all ports
    root_interface = id # a port
    root_switch_id = id # an id is an ethaddr
    pak = createStpPacket(id, 0, id)
    broadcastSPM(net, pak)
    wrappedFunc = timeWrapper(broadcast, net, pak)
    tFunc = threading.Timer(2.0, wrappedFunc)
    tFunc.start()
    notStarted = False

    while True:
        if countedDown[0] == True:
            #reset root to self with no blocked interfaces
            root_interface = id
            root_switch_id = id
            hops_to_root = 0
            blockedInterfaces = []
            countedDown[0] = False

        if root_switch_id == id:
            if notStarted:
                pak = createStpPacket(id, 0, id)
                broadcastSPM(net, pak)
                wrappedFunc = timeWrapper(broadcast, net, pak)
                tFunc = threading.Timer(2.0, wrappedFunc)
                tFunc.start()
                notStarted = False
        else:
            if notStarted == False:
                tFunc.cancel()
                notStarted = True

        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        ethernet = packet.get_header(Ethernet)
        print(packet)
        #spanning tree packet received check
        if packet.has_header(SpanningTreeMessage):
            if countdownInProgress:
                countFunc.cancel()
            wrappedCountdown = countWrapper(countdown, countedDown)
            countFunc = threading.Timer(10.1, wrappedCountdown)
            countFunc.start()
            countdownInProgress = True
            countedDown[0] = False
            #first examin root's ID. If smaller than current root, check incoming interface with root interface
            if packet[SpanningTreeMessage].root < root_switch_id:
                #update switch information - step 4
                hops_to_root = packet[SpanningTreeMessage].hops_to_root + 1
                packet[SpanningTreeMessage].hops_to_root = hops_to_root
                root_interface = input_port
                packet[SpanningTreeMessage].switch_id = id
                root_switch_id = packet[SpanningTreeMessage].root
            elif input_port == root_interface:
                #update switch information - step 4
                hops_to_root = packet[SpanningTreeMessage].hops_to_root + 1
                packet[SpanningTreeMessage].hops_to_root = hops_to_root
                root_interface = input_port
                packet[SpanningTreeMessage].switch_id = id
                root_switch_id = packet[SpanningTreeMessage].root
            #otherwise if packet root is greater than current root
            elif packet[SpanningTreeMessage].root > id:
                print("debug")
                #remove blocked interface
                for intf in blockedInterfaces:
                    if intf == input_port:
                        blockedInterfaces.remove(intf)
                continue

            #otherwise if ids match exactly
            elif packet[SpanningTreeMessage].root == root_switch_id:
                #examine number of hops to root
                if packet[SpanningTreeMessage].hops_to_root + 1 < hops_to_root:
                    #remove blocked interface
                    for intf in blockedInterfaces:
                        if intf == input_port:
                            blockedInterfaces.remove(intf)
                    #block original root interface
                    blockedInterfaces.append(root_interface)
                    #update root interface to incoming interface
                    #update switch information - step 4
                    hops_to_root = packet[SpanningTreeMessage].hops_to_root + 1
                    packet[SpanningTreeMessage].hops_to_root = hops_to_root
                    root_interface = input_port
                    packet[SpanningTreeMessage].switch_id = id
                    root_switch_id = packet[SpanningTreeMessage].root
                elif packet[SpanningTreeMessage].hops_to_root + 1 == hops_to_root:
                    if root_switch_id > packet[SpanningTreeMessage].switch_id:
                        #remove blocked interface
                        for intf in blockedInterfaces:
                            if intf == input_port:
                                blockedInterfaces.remove(intf)
                        #block original root interface
                        blockedInterfaces.append(root_interface)
                        #update root interface to incoming interface
                        #update switch information - step 4
                        hops_to_root = packet[SpanningTreeMessage].hops_to_root + 1
                        packet[SpanningTreeMessage].hops_to_root = hops_to_root
                        root_interface = input_port
                        packet[SpanningTreeMessage].switch_id = id
                        root_switch_id = packet[SpanningTreeMessage].root
                else:
                    print("Blocked {}".format(input_port))
                    blockedInterfaces.append(input_port)
                    continue

        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
            continue
        print(packet)
        #handle broadcasting when explicit address
        if ethernet.dst == BROADCAST:
            size = insertEntry(input_port, ethernet.src, size, table)
            if packet.has_header(SpanningTreeMessage):
                broadcastSPM(net, packet, input_port)
            else:
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
                if packet.has_header(SpanningTreeMessage):
                    broadcastSPM(net, packet, input_port)
                else:
                    broadcast(net, packet, input_port)
        matched = False

    net.shutdown()

#send out all ports excepted received on port and blocked ports
def broadcast(net, pkt, input_port = None):
    for port in net.ports():
        if port.name != input_port:
            if port.name not in blockedInterfaces :
                net.send_packet(port.name, pkt)

#send out all ports excepted received on port
def broadcastSPM(net, pkt, input_port = None):
    for port in net.ports():
        if port.name != input_port:
            net.send_packet(port.name, pkt)

#inserts a new entry or updates an entry in the FIFO forwarding table
def insertEntry(port, addr, size, table):
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


