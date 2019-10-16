from switchyard.lib.userlib import *

class tableEntry:
    port = -1 
    addr = -1

    def __init__(self, port, addr):
        self.port = port
        self.addr = addr

def main(net):
    BROADCAST = "ff:ff:ff:ff:ff:ff"
    size = 0
    table = []
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    matched = False

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

    #Need to before ending program
    net.shutdown()

def broadcast(net, recInfo):
    for port in net.ports():
        if port.name != recInfo.input_port:
            net.send_packet(port.name, recInfo.packet)

def insertEntry(port, addr, size, table):
        #CHECK FOR DUPLICATE ENTRIES AND DELETE OLD ONE
        entry = tableEntry(port, addr)
        if(size == 5):
            table.pop(4)
        else:
            size += 1

        table.insert(0, entry)
