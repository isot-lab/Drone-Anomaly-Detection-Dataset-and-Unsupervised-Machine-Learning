from Supporting_functions import ip_to_str
from scapy.all import *
class Connectivity_features_length:
    def __init__(self,packet):
        self.packet = packet
    def get_total_and_payload_size(self):
        packet=self.packet
        total_packet_length = 0
        ip_len = 0
        payload_length = 0
        # Check if the packet has an Ethernet layer
        if packet.haslayer(Ether):
            total_packet_length = len(packet)  # Total length of the Ethernet packet
        # Check if the packet has an IP layer
        if packet.haslayer(IP):
            ip_len = self.packet[IP].len  # Total length from the IP layer
        # Check if the packet has a UDP layer
        if packet.haslayer(UDP):
            protocol_name = "UDP"
            udp_len = packet[UDP].len  # Length from the UDP layer includes UDP header
            payload_length = udp_len - 8  # Subtract UDP header size to get data length
        # Check if the packet has a TCP layer
        elif packet.haslayer(TCP):
            protocol_name = "TCP"
            tcp_len = self.packet[TCP].dataofs * 4  # TCP data offset gives the header length in bytes
            payload_length = ip_len - (packet[IP].ihl * 4) - tcp_len  # Subtract IP and TCP header sizes from total IP length
        # Check if the packet has an ICMP layer
        elif packet.haslayer(ICMP):
            protocol_name = "ICMP"
            icmp_len = len(packet[ICMP].payload)
            payload_length = icmp_len
        # Handle other potential protocols or raw payloads
        elif self.packet.haslayer(Raw):
            protocol_name = "Raw"
            payload_length = len(packet[Raw].load)  
        return total_packet_length,payload_length
    def get_data_rate(self,payload_size,previous_time,previous_interval):
        packet=self.packet
        pre_time=previous_time
        pre_interval=previous_interval
        data_rate_mbps=0
        current_packet_time=packet.time
        time_interval = current_packet_time - pre_time
        if time_interval == 0:
            time_interval = pre_interval if pre_interval is not None else 0
        if time_interval > 0:
            data_rate_bps = (payload_size * 8) / time_interval  # Convert bytes to bits
            data_rate_mbps = data_rate_bps / 1_000_000  # Convert bits per second to megabits per second
        return time_interval,data_rate_mbps
class Connectivity_features_basic:
    def __init__(self,packet):
        self.packet = packet

    def get_source_ip(self):
        return ip_to_str(self.packet.src)

    def get_destination_ip(self):
        try:
            return ip_to_str(self.packet.dst)
        except:
            return None

    def get_source_port(self):
        return self.packet.data.sport

    def get_destination_port(self):
        return self.packet.data.dport

    def get_protocol_type(self):
        return self.packet.p

class Connectivity_features_time:
    def __init__(self,packet):
        self.packet = packet
    def duration(self):
        return self.packet.ttl

    def jitter(self):
        pass

    def inter_arrival_time(self):
        pass

    def active_time(self):
        pass

    def idle_time(self):
        pass

class Connectivity_features_flags_bytes:
    def __init__(self,packet):
        self.packet = packet
    def get_flags_count(self):
        pass

    def count(self,src_ip_byte, dst_ip_byte):
        if self.packet.src not in src_ip_byte.keys():
            src_ip_byte[self.packet.src] = 1
        else:
            src_ip_byte[self.packet.src] = src_ip_byte[self.packet.src] + 1

        if self.packet.dst not in dst_ip_byte.keys():
            dst_ip_byte[self.packet.dst] = 1
        else:
            dst_ip_byte[self.packet.dst] = dst_ip_byte[self.packet.dst] + 1


        return src_ip_byte[self.packet.src], dst_ip_byte[self.packet.dst]

