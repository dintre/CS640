#!/usr/bin/env python3
""" Testcases to test learning switch implementation i.e. part 2 of Project1 in CS640 Fall 19
Derived from : jsommers switchyard examples"""

from SpanningTreeMessage import SpanningTreeMessage        
from switchyard.lib.userlib import *


def mk_stp_pkt(root_id, hops, switch_id, hwsrc="20:00:00:00:00:01", hwdst="ff:ff:ff:ff:ff:ff"):
    spm = SpanningTreeMessage(root_id=root_id, hops_to_root=hops, switch_id=switch_id)
    Ethernet.add_next_header_class(EtherType.SLOW, SpanningTreeMessage)
    pkt = Ethernet(src=hwsrc,
                   dst=hwdst,
                   ethertype=EtherType.SLOW) + spm
    xbytes = pkt.to_bytes()
    p = Packet(raw=xbytes)
    print(p)
    return p


def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt


def hub_tests():
    s = TestScenario("Switch Tests")
    s.add_interface('eth0', '20:00:00:00:00:01')
    s.add_interface('eth1', '20:00:00:00:00:02')
    s.add_interface('eth2', '20:00:00:00:00:03')
    s.add_interface('eth3', '20:00:00:00:00:04')
    s.add_interface('eth4', '20:00:00:00:00:05')
    s.add_interface('eth5', '20:00:00:00:00:06')
    s.add_interface('eth6', '20:00:00:00:00:07')



    #1. Verify STP packet is flooded out on all ports after initialization.
    stp_pkt = mk_stp_pkt('20:00:00:00:00:01', 0, '20:00:00:00:00:01')
    s.expect(PacketOutputEvent("eth0", stp_pkt, "eth1", stp_pkt, "eth2", stp_pkt, "eth3", stp_pkt, "eth4", stp_pkt, "eth5", stp_pkt, "eth6", stp_pkt, wildcards=[(Ethernet, 'src')]), "Expecting STP packets")

    #2.3. Verify STP packet is flooded out on all ports after 2 seconds.
    s.expect(PacketInputTimeoutEvent(3), "Waiting 2 seconds")
    s.expect(PacketOutputEvent("eth0", stp_pkt, "eth1", stp_pkt, "eth2", stp_pkt, "eth3", stp_pkt, "eth4", stp_pkt, "eth5", stp_pkt, "eth6", stp_pkt, wildcards=[(Ethernet, 'src')]), "Expecting STP packets")

    #4. Receive new STP packet with smaller root.
    stp_pkt = mk_stp_pkt('10:00:00:00:00:01', 6, '10:00:00:00:00:01', hwsrc="30:00:00:00:00:01", hwdst="ff:ff:ff:ff:ff:ff")
    s.expect(PacketInputEvent("eth1", stp_pkt), "Expecting STP packets on eth1: action to be forwarded")

    #5. Verify updated STP packet is flooded out of all ports except input port
    stp_pkt = mk_stp_pkt('10:00:00:00:00:01', 7, '20:00:00:00:00:01', hwsrc="20:00:00:00:00:01", hwdst="ff:ff:ff:ff:ff:ff")
    s.expect(PacketOutputEvent("eth0", stp_pkt, "eth2", stp_pkt, "eth3", stp_pkt, "eth4", stp_pkt, "eth5", stp_pkt, "eth6", stp_pkt, wildcards=[(Ethernet, 'src')]), "Expecting STP packets to be broadcasted")

    #6. Receive new stp with same root and less hops (block eth1 in this case)
    stp_pkt = mk_stp_pkt('10:00:00:00:00:01', 4, '10:00:00:00:00:01', hwsrc="10:00:00:00:00:01", hwdst="ff:ff:ff:ff:ff:ff")
    s.expect(PacketInputEvent("eth3", stp_pkt), "Expecting STP packets on eth0: action to be forwarded")

    #7. Verify updated STP packet is flooded out of all ports except input port
    stp_pkt = mk_stp_pkt('10:00:00:00:00:01', 5, '20:00:00:00:00:01',hwsrc="20:00:00:00:00:01", hwdst="ff:ff:ff:ff:ff:ff")
    s.expect(PacketOutputEvent("eth1", stp_pkt, "eth0", stp_pkt, "eth2", stp_pkt, "eth4", stp_pkt, "eth5", stp_pkt, "eth6", stp_pkt, wildcards=[(Ethernet, 'src')]), "Expecting STP packets to be broadcasted")

    #8. Receive new stp with same root and less hops (block eth3 in this case)
    stp_pkt = mk_stp_pkt('10:00:00:00:00:01', 2, '10:00:00:00:00:01', hwsrc="10:00:00:00:00:01", hwdst="ff:ff:ff:ff:ff:ff")
    s.expect(PacketInputEvent("eth5", stp_pkt), "Expecting STP packets on eth0: action to be forwarded")

    #9. Verify updated STP packet is flooded out of all ports except input port
    stp_pkt = mk_stp_pkt('10:00:00:00:00:01', 3, '20:00:00:00:00:01',hwsrc="20:00:00:00:00:01", hwdst="ff:ff:ff:ff:ff:ff")
    s.expect(PacketOutputEvent("eth1", stp_pkt, "eth0", stp_pkt, "eth3", stp_pkt, "eth4", stp_pkt, "eth2", stp_pkt, "eth6", stp_pkt, wildcards=[(Ethernet, 'src')]), "Expecting STP packets to be broadcasted")

    #10. Receive new stp with same root and same hops but root ID > stp packet switch ID (block eth5 in this case)
    stp_pkt = mk_stp_pkt('10:00:00:00:00:01', 2, '09:00:00:00:00:01', hwsrc="10:00:00:00:00:01", hwdst="ff:ff:ff:ff:ff:ff")
    s.expect(PacketInputEvent("eth6", stp_pkt), "Expecting STP packets on eth0: action to be forwarded")

    #11. Verify updated STP packet is flooded out of all ports except input port
    stp_pkt = mk_stp_pkt('10:00:00:00:00:01', 3, '20:00:00:00:00:01',hwsrc="20:00:00:00:00:01", hwdst="ff:ff:ff:ff:ff:ff")
    s.expect(PacketOutputEvent("eth1", stp_pkt, "eth0", stp_pkt, "eth3", stp_pkt, "eth4", stp_pkt, "eth5", stp_pkt, "eth2", stp_pkt, wildcards=[(Ethernet, 'src')]), "Expecting STP packets to be broadcasted")

    #12. Receive new stp with same root and greater hops (block eth2 in this case)
    stp_pkt = mk_stp_pkt('10:00:00:00:00:01', 4, '10:00:00:00:00:01', hwsrc="10:00:00:00:00:01", hwdst="ff:ff:ff:ff:ff:ff")
    s.expect(PacketInputEvent("eth2", stp_pkt), "Expecting STP packets on eth0: action to be forwarded")

    #13. Receive new stp with bigger root
    stp_pkt = mk_stp_pkt('30:00:00:00:00:01', 0, '30:00:00:00:00:01', hwsrc="30:00:00:00:00:01", hwdst="ff:ff:ff:ff:ff:ff")
    s.expect(PacketInputEvent("eth4", stp_pkt), "Expecting STP packets on eth2: action to be discarded")


   # by the end of this port eth1, eth2, eth3, eth5 should be blocked
    # ------------------------------------------------------------------------------------------------------------
   # testing the delivery of non-stp packets

    # 14., 15.  A normal packet with destination not learnt should be sent out of ports eth0, eth4, eth6
    reqpkt = mk_pkt("60:00:00:00:00:01", "70:00:00:00:00:01", '192.168.1.100', '172.16.42.2')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
             "An Ethernet frame from 60:00:00:00:00:00 to 70:00:00:00:00:01 should arrive on eth0")
    s.expect(PacketOutputEvent("eth4", reqpkt, "eth6", reqpkt, display=Ethernet),
             "Ethernet frame destined for 70:00:00:00:00:01 should be flooded out eth4, eth6")

    # 16., 17.  A normal packet with destination  learnt should be sent out of ports where they came from.
    reqpkt = mk_pkt("70:00:00:00:00:01", "60:00:00:00:00:01", '192.168.1.100', '172.16.42.2')
    s.expect(PacketInputEvent("eth4", reqpkt, display=Ethernet),
             "An Ethernet frame from 70:00:00:00:00:01 to 60:00:00:00:00:01 should arrive on eth4")
    s.expect(PacketOutputEvent("eth0", reqpkt, display=Ethernet),
             "Ethernet frame destined for 60:00:00:00:00:01 should be flooded out only on eth0")

    #18., 19.   Verify STP packet is flooded out with self root after 10 seconds.
    stp_pkt = mk_stp_pkt('20:00:00:00:00:01', 0, '20:00:00:00:00:01')
    s.expect(PacketInputTimeoutEvent(10), "Waiting 10 seconds")
    s.expect(PacketOutputEvent("eth0", stp_pkt, "eth1", stp_pkt, "eth2", stp_pkt, "eth3", stp_pkt, "eth4", stp_pkt, "eth5", stp_pkt, "eth6", stp_pkt, wildcards=[(Ethernet, 'src')]), "Expecting STP packets")

    return s


scenario = hub_tests()

