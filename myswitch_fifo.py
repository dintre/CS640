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
    BROADCAST = "FF:FF:FF:FF:FF:FF"
    capacity = 5
    size = 0
    table = []
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    while 1:
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

        #handle broadcasting
        if ethernet.dst == BROADCAST:
            broadcast(net, recInfo)

        else:
            #loop through table
            for entry in table:
                if entry.addr == ethernet.dst:
                    print("Matched in my table! ")
                    net.send_packet(entry.port, recInfo.packet)
                else:
                    #newEntry = tableEntry(recInfo.port, ethernet.dst)
                    insertEntry(recInfo.port, ethernet.dst, size, table)
                    log_info("Added a new table entry. ")
                    broadcast(net, recInfo)

        net.send_packet(recInfo.packet)

    #Need to before ending program
    net.shutdown()

def broadcast(net, recInfo):
    for port in net.ports():
        net.send_packet(port.name, recInfo.packet)

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

def printContents(self):
    for x in self.table:
        print(x.addr)




# #class Switch

# class Switch:
#     capacity = 0
#     size = 0
#     ports = []
#     table = []
#     BROADCAST = "FF:FF:FF:FF:FF:FF"

#     def __init__(self, cap):
#         self.capacity = cap

#     def printContents(self):
#         for x in self.table:
#             print(x.addr)

#     def insertEntry(self, port, addr):
#         #CHECK FOR DUPLICATE ENTRIES AND DELETE OLD ONE
#         entry = tableEntry(port, addr)
#         if(self.size == self.capacity):
#             self.table.pop(4)
#         else:
#             self.size += 1

#         self.table.insert(0, entry)

#         for x in self.table:
#             x.self.incrementTTL()


#     def broadcast(self):

#     #def processHeader(self):

#     #def sendOnPort(self):   



# class tableEntry:
#     port = -1 
#     addr = -1
#     ttl = 0

#     def __init__(self, port, addr, ttl = 0):
#         self.port = port
#         self.addr = addr

#     def incrementTTL(self):
#         ttl += 1


# s1 = Switch(5)
# s1.insertEntry(5, "1319h")
# s1.insertEntry(3, "asd")
# s1.insertEntry(6, "31931d")
# s1.insertEntry(8, "319332321d")
# s1.insertEntry(2, "31das931d")
# s1.insertEntry(1, "3asss31d")

# s1.printContents()
