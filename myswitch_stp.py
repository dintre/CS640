'''
Ethernet learning switch in Python.
Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]

    'Add storage of host table'

    'Create packet on startup to be sent every x seconds'
    timer = 1
    spm = SpanningTreeMessage("ID", hops_to_root=1)
    idCurrentRoot = Self
    hopsToRoot = 0
    receivedSpanningTreeIntf = 'interface spanningtreepacket was received'
    timeSTPReceived = 0

    'Interface that leads to the root'
    interface = 'null for now'
    'I think switch MAC Ethaddr is in the interface so don't need an additional variable to store that'
    
    'Only initialize STP protocol if thinks self is root node, don't know how to repeat this every timer seconds'
    If idCurrentRoot = self:
    	'Building packet'
    	Ethernet.add_next_header_class(EtherType.SLOW, SpanningTreeMessage)
    	pkt = Ethernet(src="ID",dst="ID",ethertype=EtherType.SLOW) + spm
	
    'Check current time'
    If currentTime > timeSTPReceived + 30:
	idCurrentRoot = self
	'Send out packets every timer seconds'

    'I don't know if we need to check the size of the packet to ensure > 40 bytes'
    'Send out built packet along all Ports every timer seconds, don't know the code for this'

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))

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
		    	net.send_packet 'send packet out if the interface wasn't the one received'
	    elif packet[SpanningTreeMessage].root = idCurrentRoot:
		if packet[SpanningTreeMessage].hops_to_root + 1 < hopsToRoot:
		    interface = input_port
		    packet[SpanningTreeMessage].hops_to_root = packet[SpanningTreeMessage].hops_to_root + 1
		    hopsToRoot = packet[SpanningTreeMessage].hops_to_root + 1
		        for intf in my_interfaces:
                    	    if input_port != intf.name:
                    	    log_debug ("Flooding packet {} to {}".format(packet, intf.name))
		    	    net.send_packet 'send packet out if the interface wasn't the one received'
	else:
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
	    'for all normal packets, we forward in a different way'
            for intf in my_interfaces:
                if input_port != intf.name:
                    log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf.name, packet)
net.shutdown()
