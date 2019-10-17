
from switchyard.lib.userlib import *
import threading
import struct

class tableEntry:
    port = -1 
    addr = -1
    ttl = 0

    def __init__(self, port, addr, ttl = 0):
        self.port = port
        self.addr = addr


def lesserId(idOne, idTwo):
    
    if idOne < idTwo:
        return idOne
    else:
        return idTwo
    

def main(net):
    BROADCAST = "ff:ff:ff:ff:ff:ff"
    size = 0
    table = []
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    matched = False
    id = "zzzzzzzzzzzzzzzzzzzzzz"
    anythingAddr = "ef:ef:ef:ef:ef:ef"

    #find lowest port MAC for ID
    for port in net.interfaces():
        id = lesserId(id, port.ethaddr)

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

class SpanningTreeMessage(PacketHeaderBase):
    _PACKFMT = "6sxB6s"

    # switch_id is the id of the switch that forwarded the stp packet
    # in case the stp packet is generated ensure switch_id=root_id

    def __init__(self, root_id="00:00:00:00:00:00", hops_to_root=0, switch_id="00:00:00:00:00:00", **kwargs):
        self._root = EthAddr(root_id)
        self._hops_to_root = hops_to_root
        self._switch_id = EthAddr(switch_id)
        PacketHeaderBase.__init__(self, **kwargs)

    def to_bytes(self):
        raw = struct.pack(self._PACKFMT, self._root.raw, self._hops_to_root, self._switch_id.raw)
        return raw

    def from_bytes(self, raw):
        packsize = struct.calcsize(self._PACKFMT)
        if len(raw) < packsize:
            raise ValueError("Not enough bytes to unpack SpanningTreeMessage")
        xroot,xhops, xswitch = struct.unpack(self._PACKFMT, raw[:packsize])
        self._root = EthAddr(xroot)
        self.hops_to_root = xhops
        self._switch_id = EthAddr(xswitch)
        return raw[packsize:]

    @property
    def hops_to_root(self):
        return self._hops_to_root

    @hops_to_root.setter
    def hops_to_root(self, value):
        self._hops_to_root = int(value)

    @property
    def switch_id(self):
        return self._switch_id

    @switch_id.setter
    def switch_id(self, switch_id):
        self._switch_id = switch_id

    @property
    def root(self):
        return self._root

    def __str__(self):
        return "{} (root: {}, hops-to-root: {}, switch_id: {})".format(
            self.__class__.__name__, self.root, self.hops_to_root, self.switch_id)
