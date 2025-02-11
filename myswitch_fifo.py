from switchyard.lib.userlib import *
#class to keep track of one individual entry in the FIFO forwarding table
class tableEntry:
    port = -1 
    addr = -1

    def __init__(self, port, addr):
        self.port = port
        self.addr = addr
#main code entry point
def main(net):
    BROADCAST = "ff:ff:ff:ff:ff:ff"
    size = 0
    table = []
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    matched = False

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        print("Current Packet: {}".format(net.name))

        ethernet = packet.get_header(Ethernet)
        if ethernet is None:
            print("Received a non-Ethernet packet?!")
            continue

        if ethernet.dst in mymacs:
            print ("Received a packet intended for me")
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

    #Need to before ending program
    net.shutdown()

#send out all ports excepted received on port
def broadcast(net, packet, input_port):
    for port in net.ports():
        if port.name != input_port:
            net.send_packet(port.name, packet)

#inserts a new entry or updates an entry in the FIFO forwarding table
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

