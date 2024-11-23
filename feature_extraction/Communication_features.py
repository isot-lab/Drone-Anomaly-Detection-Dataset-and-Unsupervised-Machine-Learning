import binascii

import dpkt

from scapy.all import *
from scapy.layers.dot11 import Dot11, RadioTap,Dot11QoS,Dot11CCMP

class Communication_wifi:
    def __init__(self,data):
        self.data = data
    def calcualte_payload_size(self):
        packet=self.data
        if packet.haslayer(RadioTap):
            if packet.haslayer(Dot11):
                if packet.haslayer(Dot11QoS):
                    ccmp_header_size = 8
                    data_length = len(packet[Dot11QoS].payload) - ccmp_header_size
                    return data_length
                else:
                    return 0

    def calculate_packet_size(self):
        packet=self.data
        payload_data_rate=0
        if packet.haslayer(RadioTap):
            radiotap_layer = packet[RadioTap]
            # Extract the data rate in Mbps
            packet_data_rate = radiotap_layer.Rate  # Data rate is given in 0.5 Mbps units

        total_packet_size_bytes = len(packet)  # Total size of the packet

        # Calculate payload size by subtracting header sizes from total packet size
        payload_size_bytes = self.calcualte_payload_size()
        # Calculate time to transmit the entire packet (in seconds)
        if total_packet_size_bytes is not None and packet_data_rate is not None:
            transmission_time_packet = (total_packet_size_bytes * 8) / (packet_data_rate * 1_000_000)
            payload_data_rate = (payload_size_bytes * 8) / (transmission_time_packet * 1_000_000)
        # Calculate the payload data rate (in Mbps)
        if total_packet_size_bytes is None:
            total_packet_size_bytes=0
        elif payload_size_bytes is None:
            payload_size_bytes=0
        return payload_data_rate,total_packet_size_bytes,payload_size_bytes
    def calculating(self):
        # Parse the packet using Scapy's Dot11
        type_info = 0
        sub_type_info = 0
        ds_status = 0
        src_mac = 0
        dst_mac = 0
        sequence = 0
        pack_id = 0
        fragments = 0
        data_rate,total_packet_size_bytes,payload_size_bytes = 0,0,0
        packet=self.data 
        if packet.haslayer(Dot11):
            # Basic 802.11 fields
            type_info = packet.type
            sub_type_info = packet.subtype
            src_mac = packet.addr2
            dst_mac = packet.addr1

            # DS status from the FCfield (First two bits of FCfield)
            if (packet.FCfield & 0x3):
                ds_status = int(packet.FCfield & 0x3) # Only the from-DS and to-DS bits
            # Sequence control processing
            if hasattr(packet, 'SC') and packet.SC is not None:
                sequence = int(packet.SC >> 4) # Sequence number (shifted right to isolate sequence bits)
            data_rate,total_packet_size_bytes,payload_size_bytes=self.calculate_packet_size()
            # Fragments and duration/ID
            fragments = packet.FCfield & 0x4 != 0  # More Fragments bit
            # Packet ID could be interpreted in different ways; here, we assume it's a continuation of duration
            pack_id = packet.ID
        return (type_info, sub_type_info, ds_status, src_mac, dst_mac, sequence, pack_id, fragments, data_rate,total_packet_size_bytes,payload_size_bytes)

class Communication_ble:
    def __init__(self,pack):
        self.pack = pack

    def ble_features(self):
        pass

class Communication_zigbee:
    def __init__(self,pack):
        self.pack = pack

    def zigbee_features(self):
        dst_add = self.pack.destination_address
        src_add = self.pack.originator_address
        pan_id = self.pack.new_PAN_ID
        packets_len = len(self.pack)

        pass

