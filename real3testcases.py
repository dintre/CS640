import struct

from ipaddress import IPv4Address
from switchyard.lib.userlib import *
from switchyard.lib.packet import *


def mk_dynamic_routing_packet(ethdst, advertised_prefix, advertised_mask,
                               next_hop):
    drm = DynamicRoutingMessage(advertised_prefix, advertised_mask, next_hop)
    Ethernet.add_next_header_class(EtherType.SLOW, DynamicRoutingMessage)
    pkt = Ethernet(src='00:00:22:22:44:44', dst=ethdst,
                   ethertype=EtherType.SLOW) + drm
    xbytes = pkt.to_bytes()
    p = Packet(raw=xbytes)
    return p

def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl = 64):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=ttl)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt


def router_tests():
    s = TestScenario("Basic functionality testing for DynamicRoutingMessage")

    # Initialize switch with 3 ports.
    s.add_interface('router-eth0', '10:00:00:00:00:01', ipaddr = '192.168.1.1', netmask = '255.255.255.252')
    s.add_interface('router-eth1', '10:00:00:00:00:02', ipaddr = '10.10.0.1', netmask = '255.255.0.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', ipaddr = '172.16.42.1', netmask = '255.255.255.0')

    # 1 - Receive non ARP, non IPv4, non dynamic packet
    # Expected - Drop packet
    p = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
    p[UDP].src = 4444
    p[UDP].dst = 5555
    p += b'These are some application data bytes'
    s.expect(PacketInputEvent("router-eth0", p), "UDP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")

    #5 1   IP packet to be forwarded to 172.16.42.2 should arrive on
    #     router-eth0
    #         Expected event: recv_packet Ethernet
    #         10:00:00:00:00:03->30:00:00:00:00:01 IP | IPv4
    #         192.168.1.100->172.16.42.2 ICMP | ICMP EchoRequest 0 42 (0
    #         data bytes) on router-eth0

    packet = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  '30:00:00:00:00:01', ipsrc  = '192.168.1.100', ipdst = '172.16.42.2')
    s.expect(PacketInputEvent("router-eth0", packet), "IP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")

    # 6   Router should send ARP request for 172.16.42.2 out router-
    #     eth2 interface
    #         Expected event: send_packet(s) Ethernet
    #         10:00:00:00:00:03->ff:ff:ff:ff:ff:ff ARP | Arp
    #         10:00:00:00:00:03:172.16.42.1 ff:ff:ff:ff:ff:ff:172.16.42.2
    #         out router-eth2

    arp_request  = create_ip_arp_request('10:00:00:00:00:03', '172.16.42.1', '172.16.42.2')
    s.expect(PacketOutputEvent("router-eth2", arp_request), "Router should send ARP request for 172.16.42.2 out router-eth2 interface")

    # 7   Router should receive ARP response for 172.16.42.2 on
    #     router-eth2 interface
    #         Expected event: recv_packet Ethernet
    #         30:00:00:00:00:01->10:00:00:00:00:03 ARP | Arp
    #         30:00:00:00:00:01:172.16.42.2 10:00:00:00:00:03:172.16.42.1
    #         on router-eth2

    arp_response = create_ip_arp_reply('30:00:00:00:00:01', '10:00:00:00:00:03',
                                       '172.16.42.2', '172.16.42.1')
    s.expect(PacketInputEvent("router-eth2", arp_response), "Router should receive ARP response for 172.16.42.2 on router-eth2 interface")


    # 8   IP packet should be forwarded to 172.16.42.2 out router-eth2
    #         Expected event: send_packet(s) Ethernet
    #         10:00:00:00:00:03->30:00:00:00:00:01 IP | IPv4
    #         192.168.1.100->172.16.42.2 ICMP | ICMP EchoRequest 0 42 (0
    #         data bytes) out router-eth2

    packet = mk_pkt(hwsrc='10:00:00:00:00:03', hwdst='30:00:00:00:00:01', ipsrc='192.168.1.100', ipdst='172.16.42.2', ttl=63)
    s.expect(PacketOutputEvent("router-eth2", packet), "IP packet should be forwarded to 192.168.1.1 out router-eth2")


    # 2 - Receive ARP Request that is NOT router's own port
    # Expected - drop packet
    arp_request  = create_ip_arp_request('10:00:00:00:00:06', '172.16.42.1', '172.16.42.2')
    s.expect(PacketInputEvent("router-eth0", arp_request), "ARP request should arrive on router-eth0 and be dropped. Not in own ports")

    # 3 - Receive ARP Request that is for one of your router's own ports
    # Expected - send arp reply
    arp_request  = create_ip_arp_request('30:00:00:00:00:02', '172.16.99.1', '10.10.0.1')
    s.expect(PacketInputEvent("router-eth0", arp_request), "ARP request should arrive on router-eth0, for own port")

    # 4 - send ARP response
    # Expected - send arp response to case 3
    arp_response = create_ip_arp_reply('10:00:00:00:00:02', '30:00:00:00:00:02',
                                       '10.10.0.1', '172.16.99.1')
    s.expect(PacketOutputEvent("router-eth0", arp_response), "Router should send ARP response for 172.16.99.1 out router-eth0 interface")



    #9 packet that matches in fTable. Needs ARP request. tries 3 times and stops
    packet = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  '30:00:00:00:00:01', ipsrc  = '192.16.42.2', ipdst = '192.168.1.2')
    s.expect(PacketInputEvent("router-eth0", packet), "IP packet to be forwarded to 172.19.42.2 should arrive on router-eth0")

    #9.2
    arp_request  = create_ip_arp_request('10:00:00:00:00:01', '192.168.1.1', '192.168.1.2')
    s.expect(PacketOutputEvent("router-eth0", arp_request), "Router should send ARP request for 192.168.1.2 out router-eth2 interface")

    #9.3
    s.expect(PacketInputTimeoutEvent(1), "Waiting 1 seconds")

    # 1 - Receive non ARP, non IPv4, non dynamic packet
    # Expected - Drop packet
    p = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
    p[UDP].src = 4444
    p[UDP].dst = 5555
    p += b'These are some application data bytes'
    s.expect(PacketInputEvent("router-eth0", p), "UDP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")

    #9.4
    s.expect(PacketOutputEvent("router-eth0", arp_request), "Router should send ARP request for 192.168.1.2 out router-eth2 interface")

    #9.5
    s.expect(PacketInputTimeoutEvent(1), "Waiting 1 seconds")

  #5 1   IP packet to be forwarded to 172.16.42.2 should arrive on
    #     router-eth0
    #         Expected event: recv_packet Ethernet
    #         10:00:00:00:00:03->30:00:00:00:00:01 IP | IPv4
    #         192.168.1.100->172.16.42.2 ICMP | ICMP EchoRequest 0 42 (0
    #         data bytes) on router-eth0

    packet = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  '30:00:00:00:00:01', ipsrc  = '192.168.1.100', ipdst = '172.16.42.2')
    s.expect(PacketInputEvent("router-eth0", packet), "IP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")


    #9.6 or 14
    s.expect(PacketOutputEvent("router-eth0", arp_request), "Router should send ARP request for 192.168.1.2 out router-eth2 interface")

    # 1 - Receive non ARP, non IPv4, non dynamic packet
    # Expected - Drop packet
    p = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
    p[UDP].src = 4444
    p[UDP].dst = 5555
    p += b'These are some application data bytes'
    s.expect(PacketInputEvent("router-eth0", p), "UDP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")


    #9 packet that matches in fTable. Needs ARP request. tries 3 times and stops
    packet = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  '30:00:00:00:00:01', ipsrc  = '192.16.42.2', ipdst = '192.168.1.2')
    s.expect(PacketInputEvent("router-eth0", packet), "IP packet to be forwarded to 172.19.42.2 should arrive on router-eth0")

    #9.2
    arp_request  = create_ip_arp_request('10:00:00:00:00:01', '192.168.1.1', '192.168.1.2')
    s.expect(PacketOutputEvent("router-eth0", arp_request), "Router should send ARP request for 192.168.1.2 out router-eth2 interface")

    #9.3
    s.expect(PacketInputTimeoutEvent(1), "Waiting 1 seconds")

    # 1 - Receive non ARP, non IPv4, non dynamic packet
    # Expected - Drop packet
    p = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
    p[UDP].src = 4444
    p[UDP].dst = 5555
    p += b'These are some application data bytes'
    s.expect(PacketInputEvent("router-eth0", p), "UDP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")

    #9.2
    arp_request  = create_ip_arp_request('10:00:00:00:00:01', '192.168.1.1', '192.168.1.2')
    s.expect(PacketOutputEvent("router-eth0", arp_request), "Router should send ARP request for 192.168.1.2 out router-eth2 interface")

    #yay a reply comes
    arp_response = create_ip_arp_reply('30:00:00:00:00:01', '10:00:00:00:00:01',
                                       '192.168.1.2', '192.168.1.1')
    s.expect(PacketInputEvent("router-eth2", arp_response), "Router should receive ARP response for 172.16.42.2 on router-eth2 interface")

    # forward both queued packets now
    pkt = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  '30:00:00:00:00:01', ipsrc  = '192.16.42.2', ipdst = '192.168.1.2', ttl=63)

    s.expect(PacketOutputEvent("router-eth2", pkt), "IP packet should be forwarded to 192.168.1.2 out router-eth2")


    return s

scenario = router_tests()



