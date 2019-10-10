from switchyard.switchyard.lib.userlib import *

def main(netObj):
    BROADCAST = "FF:FF:FF:FF:FF:FF"
    capacity = 5
    size = 0
    table = []

class tableEntry:
    port = -1 
    addr = -1
    ttl = 0

    def __init__(self, port, addr, ttl = 0):
        self.port = port
        self.addr = addr

    def incrementTTL(self):
        ttl += 1

    def printContents(self):
        for x in self.table:
            print(x.addr)

    def insertEntry(self, port, addr):
        #CHECK FOR DUPLICATE ENTRIES AND DELETE OLD ONE
        entry = tableEntry(port, addr)
        if(self.size == self.capacity):
            self.table.pop(4)
        else:
            self.size += 1

        self.table.insert(0, entry)

        for x in self.table:
            x.self.incrementTTL()

    while 1:
        try:
            recInfo = netObj.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug("Current Packet: {}".format(net.name))

        ethernet = recInfo.packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            continue

        if eth.dst in mymacs:
            log_info ("Received a packet intended for me")

        else:
            #loop through table
            for entry in table:
                if entry.addr == ethernet.dst:
                    log_info("Matched in my table! ")
                else:
                    newEntry = tableEntry(recInfo.port, ethernet.dst)
                    log_info("Added a new table entry. ")


    #Need to before ending program
    netObj.shutdown()


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
