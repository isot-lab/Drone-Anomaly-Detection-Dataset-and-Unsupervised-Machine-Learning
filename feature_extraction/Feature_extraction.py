import dpkt
import pandas as pd
import json
from scapy.all import *
from Communication_features import Communication_wifi, Communication_zigbee
from Connectivity_features import Connectivity_features_basic, Connectivity_features_time, \
    Connectivity_features_flags_bytes,Connectivity_features_length
from Dynamic_features import Dynamic_features
from Layered_features import L3, L4, L2, L1
from Supporting_functions import get_protocol_name, get_flow_info, get_flag_values, compare_flow_flags, \
    get_src_dst_packets, calculate_incoming_connections, \
    calculate_packets_counts_per_ips_proto, calculate_packets_count_per_ports_proto,extract_oui,\
    oui_hex_to_float,calculate_entropy
from tqdm import tqdm
import time

from scapy.layers.dot11 import Dot11, RadioTap, Dot11Beacon, Dot11QoS, Dot11CCMP
from scapy.all import rdpcap, Ether, IP, TCP, UDP, DNS


class Feature_extraction():
    columns = ["ts","Payload_Length",
              "Source IP","Destination IP","Source Port","Destination Port","Protocol Type","Protocol_name",
              "Duration","src_ip_bytes","dst_ip_bytes","src_pkts","dst_pkts", "Rate", "Srate", "Drate"
               ,"TNP_per_proto_tcp","TNP_per_proto_udp","fin_flag_number","syn_flag_number","rst_flag_number"
               ,"psh_flag_number","ack_flag_number","urg_flag_number","ece_flag_number","cwr_flag_number",
               "ack_count", "syn_count", "fin_count", "urg_count", "rst_count", 
              
               "max_duration","min_duration","sum_duration","average_duration","std_duration",
               "MQTT", "CoAP", "HTTP", "HTTPS", "DNS", "Telnet","SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP","ARP", "ICMP", "IGMP", "IPv", "LLC",
    "Tot sum", "Min", "Max", "AVG", "Std","Tot size", "IAT", "Number", "MAC", "Magnitue", "Radius", "Covariance", "Variance", "Weight",
               "Wifi_Type", "Wifi_Subtype", "DS status", "Fragments", "wifi_src", "wifi_dst", "Sequence number", "Protocol Version",
               "flow_idle_time", "flow_active_time"

    ]
    def __init__(self):
        self.wifi_flows = {}
        self.ip="192.168.10.1" #for the particular tello edu drone in this project
        self.mac="60:60:1f:58:ec:cc"
        self.base_row = {c: [] for c in self.columns}

    def pcap_evaluation(self,pcap_file,csv_file_name):
        global ethsize, src_ports, dst_ports, src_ips, dst_ips, ips , tcpflows, udpflows, src_packet_count, dst_packet_count, src_ip_byte, dst_ip_byte
        global protcols_count, tcp_flow_flgs, incoming_packets_src, incoming_packets_dst, packets_per_protocol, average_per_proto_src
        global average_per_proto_dst, average_per_proto_src_port, average_per_proto_dst_port
        columns = ["ts","Payload_Length",
                  "Protocol Type","Protocol_name",
                  "Duration","Drone_port","OUI","Entropy","Var_Payload",
                  "Rate", "Srate", "Drate"
                   ,"fin_flag_number","syn_flag_number","rst_flag_number"
                   ,"psh_flag_number","ack_flag_number","urg_flag_number","ece_flag_number","cwr_flag_number",
                   "ack_count", "syn_count", "fin_count", "urg_count", "rst_count", 
                 
                   "max_duration","min_duration","sum_duration","average_duration","std_duration",
                 
                   "CoAP", "HTTP", "HTTPS", "DNS", "Telnet","SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP","ARP", "ICMP", "IGMP", "IPv", "LLC",
        "Tot sum", "Min", "Max", "AVG", "Std","Tot size", "IAT", "Number", "Magnitue", "Radius", "Covariance", "Variance", "Weight",
                 
                   "DS status", "Fragments", 
                 
                   "Sequence number", "Protocol Version",
                   "flow_idle_time", "flow_active_time"

        ]
        base_row = {c:[] for c in columns}
        start = time.time()
        ethsize = []
        src_ports = {}  # saving the number of source port used
        dst_ports = {}  # saving the number of destination port used
        tcpflows = {}  # saving the whole tcpflows
        udpflows = {}  # saving the whole udpflows
        src_packet_count = {}  # saving the number of packets per source IP
        dst_packet_count = {}  # saving the number of packets per destination IP
        dst_port_packet_count = {}  # saving the number of packets per destination port
        src_ip_byte, dst_ip_byte = {}, {}
        tcp_flow_flags = {}  # saving the number of flags for each flow
        packets_per_protocol = {}   # saving the number of packets per protocol
        average_per_proto_src = {}  # saving the number of packets per protocol and src_ip
        average_per_proto_dst = {}  # saving the number of packets per protocol and dst_ip
        average_per_proto_src_port, average_per_proto_dst_port = {}, {}    # saving the number of packets per protocol and src_port and dst_port
        ips = set()  # saving unique IPs
        number_of_packets_per_trabsaction = 0  # saving the number of packets per transaction
        rate, srate, drate = 0, 0, 0
        max_duration, min_duration, sum_duration, average_duration, std_duration = 0, 0, 0, 0, 0   # duration-related features of aggerated records
        total_du = 0
        first_pac_time = 0
        last_pac_time = 0
        incoming_pack = []
        outgoing_pack = []
        f = open(pcap_file, 'rb')
        pcap = dpkt.pcap.Reader(f)
        ## Using SCAPY for Zigbee and blutooth ##
        scapy_pak = rdpcap(pcap_file)
        count = 0  # counting the packets
        count_rows = 0
        previous_time=None
        previous_interval=None
        previous_11_time=None
        previous_11_interval=None
        for ts, buf in (pcap):
            if type(scapy_pak[count]) == scapy.layers.bluetooth:
                pass
            elif type(scapy_pak[count]) == scapy.layers.zigbee.ZigbeeNWKCommandPayload:
                zigbee = Communication_zigbee(scapy_pak[count])
            try:
               eth = dpkt.ethernet.Ethernet(buf)
               sp=scapy_pak[count]
               if scapy_pak[count].haslayer(Dot11):
                    eth=scapy_pak[count]
               count = count + 1
            except:
                count = count + 1
                continue  # If packet format is not readable by dpkt, discard the packet
            ethernet_frame_size = len(eth)
            ethernet_frame_type = eth.type
            total_du = total_du + ts
            # initilization #
            src_port, src_ip, dst_port, duration = 0, 0, 0, 0
            dst_ip, proto_type, protocol_name = 0, 0, "" 
            ptl, payload_byte = 0, 0
            flow_duration,flow_byte=0,0
            src_byte_count, dst_byte_count = 0, 0
            src_pkts, dst_pkts = 0, 0
            connection_status = 0
            number = 0
            IAT = None
            src_to_dst_pkt, dst_to_src_pkt = 0, 0  # count of packets from src to des and vice-versa
            src_to_dst_byte, dst_to_src_byte = 0, 0  # Total bytes of packets from src to dst and vice-versa
            # flags
            flag_valus = []  # numerical values of packet(TCP) flags
            ack_count, syn_count, fin_count, urg_count, rst_count = 0, 0, 0, 0, 0
            # Layered flags
            udp, tcp, http, https, arp, smtp, irc, ssh, dns, ipv, icmp, igmp, mqtt, coap = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            telnet, dhcp, llc, mac, rarp = 0, 0, 0, 0, 0
            sum_packets, min_packets, max_packets, mean_packets, std_packets = 0, 0, 0, 0, 0
            magnite, radius, correlation, covaraince, var_ratio, weight = 0, 0, 0, 0, 0, 0
            idle_time, active_time = 0, 0
            type_info, sub_type_info, ds_status, src_mac, dst_mac, sequence, pack_id, fragments, wifi_dur,rate,ptl,payload_byte = 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0
            oui=0
            entropy=0
            var_payload=0
            pro_version=0
            if eth.type in [0,1,2]: # for wifi 802.11
                if isinstance(eth, Packet) and eth.haslayer(Dot11):   # Wifi packets
                    wifi_info = Communication_wifi(eth)
                    drone_port=-1
                    type_info, sub_type_info, ds_status, src_mac, dst_mac, sequence, pack_id, fragments,rate,ptl,payload_byte= wifi_info.calculating()
                    # Track frames between MAC addresses

                    default_mac_addresses = ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"]

                    if not src_mac:
                        if dst_mac == default_mac_addresses[0]:
                            src_mac = default_mac_addresses[1]
                        else:
                            src_mac = default_mac_addresses[0]

                    if not dst_mac:
                        if src_mac == default_mac_addresses[0]:
                            dst_mac = default_mac_addresses[1]
                        else:
                            dst_mac = default_mac_addresses[0]

                    flow = tuple([src_mac, dst_mac])
                    if src_mac==self.mac:
                        oui=extract_oui(src_mac)
                    elif dst_mac==self.mac:
                        oui=extract_oui(dst_mac)
                    flow_data = {
                        'byte_count': len(eth),
                        'ts': ts
                    }
                    if flow in self.wifi_flows:
                        self.wifi_flows[flow].append(flow_data)
                    else:
                        self.wifi_flows[flow] = [flow_data]
                    packets = self.wifi_flows[flow]
                    number_of_packets_per_transaction = len(packets)
                    flow_byte, flow_duration, max_duration, min_duration, sum_duration, avg_duration, std_duration, idle_time, active_time = get_flow_info(self.wifi_flows, flow)
                    src_to_dst_pkt, dst_to_src_pkt, src_to_dst_byte, dst_to_src_byte = get_src_dst_packets(self.wifi_flows, flow)
                    ethsize.append(ethernet_frame_size)
                    srcs = {}
                    dsts = {}
                    if previous_11_time is None:  
                        IAT = 0
                        previous_11_time = ts 
                    else:
                        IAT = ts - previous_11_time
                        previous_11_time = ts
                    if len(ethsize) % 20 == 0:
                        dy = Dynamic_features()    # Dynamic_features based on size of packets
                        sum_packets, min_packets, max_packets, mean_packets, std_packets = dy.dynamic_calculation(ethsize)
                        magnite, radius, correlation, covaraince, var_ratio, weight = dy.dynamic_two_streams(incoming_pack,
                                                                                                             outgoing_pack)
                        ethsize = []
                        srcs = {}
                        dsts = {}
                        incoming_pack = []
                        outgoing_pack = []
                    else:
                        dy = Dynamic_features()
                        sum_packets, min_packets, max_packets, mean_packets, std_packets = dy.dynamic_calculation(ethsize)
                        dst = dst_mac
                        src = src_mac
                        if src in dsts:
                            outgoing_pack.append(ethernet_frame_size)
                        else:
                            dsts[src] = 1
                            outgoing_pack.append(ethernet_frame_size)

                        if dst in srcs:
                            incoming_pack.append(ethernet_frame_size)
                        else:
                            srcs[dst] = 1
                            incoming_pack.append(ethernet_frame_size)
                        magnite, radius, correlation, covaraince, var_ratio, weight = dy.dynamic_two_streams(incoming_pack,
                                                                                            outgoing_pack)
                    # Initialize variables to avoid UnboundLocalError
                    srate = drate = 0
                    if flow_duration != 0:
                        srate = src_to_dst_pkt / flow_duration
                        drate = dst_to_src_pkt / flow_duration
                    proto_type=802.11
                    potential_packet=eth
                
                    # L1_features
                    l_one = L1(potential_packet)
                    llc = l_one.LLC()
                    if len(flag_valus) == 0:
                        for i in range(0,8):
                            flag_valus.append(0)
                    pro_version=802.11
                    new_row = {"ts": ts, 
                               "Protocol_name": protocol_name, 
                               "Duration": wifi_dur, #ieee802.11 does not have ip layer and ttl
                               'Protocol Type': proto_type, 
                              "Payload_Length": payload_byte, 
                              "Var_Payload":var_payload, 
                              "src_ip_bytes": src_byte_count, 
                              "fin_flag_number": flag_valus[0],
                              "syn_flag_number":flag_valus[1],
                              "rst_flag_number":flag_valus[2],
                              "psh_flag_number": flag_valus[3],
                              "ack_flag_number": flag_valus[4],
                              "urg_flag_number": flag_valus[5],
                              "ece_flag_number":flag_valus[6],
                              "cwr_flag_number":flag_valus[7],
                               "dst_ip_bytes": dst_byte_count, 
                               "Drone_port":drone_port, #802.11 does not use any port, assign -1
                               "OUI":oui,  
                               "Entropy":entropy,                             
                               "Rate": rate, #Mb/s
                               "Srate": srate, 
                               "Drate": drate, 
                               "ack_count":ack_count, 
                               "syn_count":syn_count, 
                               "fin_count": fin_count, 
                               "urg_count": urg_count, 
                               "rst_count": rst_count,
                               "max_duration": max_duration,
                               "min_duration": min_duration,
                               "sum_duration": sum_duration,
                               "average_duration": avg_duration,
                               "std_duration": std_duration,
                               "CoAP": coap, 
                               "HTTP": http, 
                               "HTTPS": https, 
                               "DNS": dns, 
                               "Telnet":telnet,
                               "SMTP": smtp, 
                               "SSH": ssh, 
                               "IRC": irc, 
                               "TCP": tcp, 
                               "UDP": udp, 
                               "DHCP": dhcp,
                               "ARP": arp, 
                               "ICMP": icmp, 
                               "IGMP": igmp, 
                               "IPv": ipv, 
                               "LLC": llc,
                               "Tot sum":sum_packets, 
                               "Min": min_packets, 
                               "Max": max_packets, 
                               "AVG": mean_packets, 
                               "Std": std_packets,
                               "Tot size": ethernet_frame_size, 
                               "IAT": IAT, 
                               "Number": len(ethsize), 
                               "Magnitue": magnite, 
                               "Radius":radius, 
                               "Covariance":covaraince, 
                               "Variance":var_ratio, 
                               "Weight": weight,
                               "Correlation": correlation, 
                               "RARP": rarp, 
                               "DS status":ds_status,
                               "Fragments":fragments,
                               "Sequence number":sequence,
                               "Protocol Version": pro_version,
                               "flow_idle_time":idle_time,
                               "flow_active_time":active_time}
                    for c in base_row.keys():
                        base_row[c].append(new_row[c])

                    count_rows+=1
            if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_ARP:
                ethsize.append(ethernet_frame_size)
                srcs = {}
                dsts = {}
                drone_port=-1
                if len(ethsize) % 20 == 0:
                    dy = Dynamic_features()    # Dynamic_features based on size of packets
                    sum_packets, min_packets, max_packets, mean_packets, std_packets = dy.dynamic_calculation(ethsize)
                    magnite, radius, correlation, covaraince, var_ratio, weight = dy.dynamic_two_streams(incoming_pack,
                                                                                                         outgoing_pack)
                    ethsize = []
                    srcs = {}
                    dsts = {}
                    incoming_pack = []
                    outgoing_pack = []
                else:
                    dy = Dynamic_features()
                    sum_packets, min_packets, max_packets, mean_packets, std_packets = dy.dynamic_calculation(ethsize)
                    con_basic = Connectivity_features_basic(eth.data)
                    dst = con_basic.get_destination_ip()
                    src = con_basic.get_destination_ip()
                    if src in dsts:
                        outgoing_pack.append(ethernet_frame_size)
                    else:
                        dsts[src] = 1
                        outgoing_pack.append(ethernet_frame_size)

                    if dst in srcs:
                        incoming_pack.append(ethernet_frame_size)
                    else:
                        srcs[dst] = 1
                        incoming_pack.append(ethernet_frame_size)
                    magnite, radius, correlation, covaraince, var_ratio, weight = dy.dynamic_two_streams(incoming_pack,
                                                                                                         outgoing_pack)
            
                if eth.type == dpkt.ethernet.ETH_TYPE_IP:     # IP packets
            
                    ipv = 1
                    ip = eth.data
                    con_basic = Connectivity_features_basic(ip)

                    #Dynamic_packets
                    dy = Dynamic_features()
          


                    # Connectivity_basic_features
                    src_ip = con_basic.get_source_ip()

                    proto_type = con_basic.get_protocol_type()
                    dst_ip = con_basic.get_destination_ip()
                    conn_length=Connectivity_features_length(sp)
                    ptl,payload_byte=conn_length.get_total_and_payload_size()
                    pro_version=sp.version
                    if previous_time is None:
                        previous_time=sp.time
                        continue
                    time_interval,rate=conn_length.get_data_rate(payload_byte,previous_time,previous_interval)
                    if time_interval!=previous_interval:
                        IAT=time_interval
                    previous_interval=time_interval
                    previous_time=sp.time
                    ips.add(dst_ip)
                    ips.add(src_ip)
                    entropy=calculate_entropy(sp)
                    # Connectivity_time_features
                    con_time = Connectivity_features_time(ip)
                    duration = con_time.duration()
                    potential_packet = ip.data

                    # Connectivity_features_flags_bytes
                    conn_flags_bytes = Connectivity_features_flags_bytes(ip)
                    src_byte_count, dst_byte_count = conn_flags_bytes.count(src_ip_byte, dst_ip_byte)

                    # L_three_layered_features
                    l_three = L3(potential_packet)
                    udp = l_three.udp()
                    tcp = l_three.tcp()

                    protocol_name = get_protocol_name(proto_type)
                    if protocol_name == "ICMP":
                        icmp = 1
                    elif protocol_name == "IGMP":
                        igmp = 1
                    # L1_features
                    l_one = L1(potential_packet)
                    llc = l_one.LLC()
                    mac = l_one.MAC()


                    # Extra features of Bot-IoT and Ton-IoT

                    # Average rate features
                    calculate_packets_counts_per_ips_proto(average_per_proto_src, protocol_name, src_ip, average_per_proto_dst,
                                              dst_ip)
                    calculate_packets_count_per_ports_proto(average_per_proto_src_port, average_per_proto_dst_port,
                                                            protocol_name, src_port, dst_port)
                    #----end of Average rate features ---#

                    # if packets_per_protocol.get(protocol_name):
                    #     packets_per_protocol[protocol_name] = packets_per_protocol[protocol_name] + 1
                    # else:
                    #     packets_per_protocol[protocol_name] = 1

                    # if protocol_name in protcols_count.keys():
                    #     protcols_count[protocol_name] = protcols_count[protocol_name] + 1
                    # else:
                    #     protcols_count[protocol_name] = 1



                    if src_ip not in src_packet_count.keys():
                        src_packet_count[src_ip] = 1
                    else:
                        src_packet_count[src_ip] = src_packet_count[src_ip] + 1


                    if dst_ip not in dst_packet_count.keys():
                        dst_packet_count[dst_ip] = 1
                    else:
                        dst_packet_count[dst_ip] = dst_packet_count[dst_ip] + 1

                    src_pkts, dst_pkts = src_packet_count[src_ip], dst_packet_count[dst_ip]
                    l_four_both = L4(src_port, dst_port)
                    coap = l_four_both.coap()
                    smtp = l_four_both.smtp()
                    # Features related to UDP
                    if type(potential_packet) == dpkt.udp.UDP:
                        src_port = con_basic.get_source_port()
                        dst_port = con_basic.get_destination_port()
                        if sp[IP].src==self.ip:
                            drone_port=src_port
                            if sp.haslayer(Ether):
                                oui=extract_oui(sp[Ether].src)
                        elif sp[IP].dst==self.ip:
                            drone_port=dst_port
                            if sp.haslayer(Ether):
                                oui=extract_oui(sp[Ether].dst)
                        # L4 features
                        l_four = L4(src_port, dst_port)
                        l_two = L2(src_port, dst_port)
                        dhcp = l_two.dhcp()
                        dns = l_four.dns()
                        if dst_port in dst_port_packet_count.keys():
                            dst_packet_count[dst_port] = dst_port_packet_count[dst_port] + 1
                        else:
                            dst_packet_count[dst_port] = 1
                        flow = [(src_ip, src_port), (dst_ip, dst_port)]
                        flow = (flow[0], flow[1])
                        flow_data = {
                            'byte_count': len(eth),
                            'ts': ts
                        }
                        if udpflows.get(flow):
                            udpflows[flow].append(flow_data)
                        else:
                            udpflows[flow] = [flow_data]
                        packets = udpflows[flow]
                        number_of_packets_per_trabsaction = len(packets)
                        flow_byte, flow_duration, max_duration, min_duration, sum_duration, average_duration, std_duration, idle_time,active_time = get_flow_info(udpflows,flow)
                        src_to_dst_pkt, dst_to_src_pkt, src_to_dst_byte, dst_to_src_byte = get_src_dst_packets(udpflows, flow)
                    # Features related to TCP
                    elif type(potential_packet) == dpkt.tcp.TCP:
                        src_port = con_basic.get_source_port()
                        dst_port = con_basic.get_destination_port()
                        if dst_port in dst_port_packet_count.keys():
                            dst_packet_count[dst_port] = dst_port_packet_count[dst_port] + 1
                        else:
                            dst_packet_count[dst_port] = 1
                        if sp[IP].src==self.ip:
                            drone_port=src_port
                            if sp.haslayer(Ether):
                                oui=extract_oui(sp[Ether].src)
                        elif sp[IP].dst==self.ip:
                            drone_port=dst_port
                            if sp.haslayer(Ether):
                                oui=extract_oui(sp[Ether].dst)
                        flag_valus = get_flag_values(ip.data)
                        # L4 features based on TCP
                        l_four = L4(src_port,dst_port)
                        http = l_four.http()
                        https = l_four.https()
                        ssh = l_four.ssh()
                        irc = l_four.IRC()
                        smtp = l_four.smtp()
                        mqtt = l_four.mqtt()
                        telnet = l_four.telnet()

                        try:
                            http_info = dpkt.http.Response(ip.data)
                            connection_status = http_info.status
                        except:
                            # print("No status")
                            connection_status = 0


                        flow = [(src_ip, src_port), (dst_ip, dst_port)]
                        flow = (flow[0], flow[1])
                        flow_data = {
                            'byte_count': len(eth),
                            'ts': ts
                        }
                        if tcpflows.get(flow):
                            tcpflows[flow].append(flow_data)
                            # comparing Flow state based on its flags
                            ack_count, syn_count, fin_count, urg_count, rst_count = tcp_flow_flags[flow]
                            ack_count,syn_count,fin_count,urg_count,rst_count = compare_flow_flags(flag_valus,ack_count,syn_count,fin_count,urg_count,rst_count)
                            tcp_flow_flags[flow] = [ack_count, syn_count, fin_count, urg_count, rst_count]
                        else:
                            tcpflows[flow] = [flow_data]
                            ack_count,syn_count,fin_count,urg_count,rst_count = compare_flow_flags(flag_valus, ack_count, syn_count, fin_count, urg_count, rst_count)
                            tcp_flow_flags[flow] = [ack_count,syn_count,fin_count,urg_count,rst_count]

                        packets = tcpflows[flow]
                        number_of_packets_per_trabsaction = len(packets)
                        flow_byte, flow_duration,max_duration,min_duration,sum_duration,average_duration,std_duration,idle_time,active_time = get_flow_info(tcpflows,flow)
                        src_to_dst_pkt, dst_to_src_pkt, src_to_dst_byte, dst_to_src_byte = get_src_dst_packets(tcpflows, flow)

                    # calculate_incoming_connections(incoming_packets_src, incoming_packets_dst, src_port, dst_port, src_ip, dst_ip)
                    if flow_duration != 0:
                        srate = src_to_dst_pkt / flow_duration
                        drate = dst_to_src_pkt / flow_duration

                    if dst_port_packet_count.get(dst_port):
                        dst_port_packet_count[dst_port] = dst_port_packet_count[dst_port] + 1
                    else:
                        dst_port_packet_count[dst_port] = 1









                elif eth.type == dpkt.ethernet.ETH_TYPE_ARP:   # ARP packets
                    # print("ARP packet")
                    protocol_name = "ARP"
                    arp = 1
                    if packets_per_protocol.get(protocol_name):
                        packets_per_protocol[protocol_name] = packets_per_protocol[protocol_name] + 1
                    else:
                        packets_per_protocol[protocol_name] = 1


                    calculate_packets_counts_per_ips_proto(average_per_proto_src, protocol_name, src_ip, average_per_proto_dst,
                                              dst_ip)
                elif eth.type == dpkt.ethernet.ETH_TYPE_REVARP:  # RARP packets
                    rarp = 1   # Reverce of ARP

                # Average rate features
                # for key in average_per_proto_src:
                #     AR_P_Proto_P_SrcIP[key] = average_per_proto_src[key] / total_du

                # for key in average_per_proto_dst:
                #     AR_P_Proto_P_Dst_IP[key] = average_per_proto_dst[key] / total_du

                # for key in average_per_proto_src_port:
                #     ar_p_proto_p_src_sport[key] = average_per_proto_src_port[key] / total_du

                # for key in average_per_proto_dst_port:
                #     ar_p_proto_p_dst_dport[key] = average_per_proto_dst_port[key] / total_du

                # end of average rate features
                if len(flag_valus) == 0:
                    for i in range(0,8):
                        flag_valus.append(0)

                
                new_row = {"ts": ts, 
                           "Protocol_name": protocol_name, 
                           "Duration": duration, 
                           'Protocol Type': proto_type,  
                            "Payload_Length": payload_byte,
                            "Var_Payload":var_payload, 
                          "src_ip_bytes": src_byte_count, 
                          "fin_flag_number": flag_valus[0],
                          "syn_flag_number":flag_valus[1],
                          "rst_flag_number":flag_valus[2],
                          "psh_flag_number": flag_valus[3],
                          "ack_flag_number": flag_valus[4],
                          "urg_flag_number": flag_valus[5],
                          "ece_flag_number":flag_valus[6],
                          "cwr_flag_number":flag_valus[7],
                           "dst_ip_bytes": dst_byte_count, 
                           "Drone_port":drone_port,
                           "OUI":oui,
                           "Entropy":entropy,
                           "Rate": rate, 
                           "Srate": srate, 
                           "Drate": drate, 
                           "ack_count":ack_count, 
                           "syn_count":syn_count, 
                           "fin_count": fin_count, 
                           "urg_count": urg_count, 
                           "rst_count": rst_count,
                           "max_duration": max_duration,
                           "min_duration": min_duration,
                           "sum_duration": sum_duration,
                           "average_duration": average_duration,
                           "std_duration": std_duration,
                           "CoAP": coap, 
                           "HTTP": http, 
                           "HTTPS": https, 
                           "DNS": dns, 
                           "Telnet":telnet,
                           "SMTP": smtp, 
                           "SSH": ssh, 
                           "IRC": irc, 
                           "TCP": tcp, 
                           "UDP": udp, 
                           "DHCP": dhcp,
                           "ARP": arp, 
                           "ICMP": icmp, 
                           "IGMP": igmp, 
                           "IPv": ipv, 
                           "LLC": llc,
                           "Tot sum":sum_packets, 
                           "Min": min_packets, 
                           "Max": max_packets, 
                           "AVG": mean_packets, 
                           "Std": std_packets,
                           "Tot size": ethernet_frame_size, 
                           "IAT": IAT, 
                           "Number": len(ethsize), 
                           "Magnitue": magnite, 
                           "Radius":radius, 
                           "Covariance":covaraince, 
                           "Variance":var_ratio, 
                           "Weight": weight,
                           "Correlation": correlation, 
                           "RARP": rarp, 
                           "DS status":ds_status,
                           "Fragments":fragments,
                           "Sequence number":sequence,
                           "Protocol Version": pro_version,
                           "flow_idle_time":idle_time,
                           "flow_active_time":active_time}
                for c in base_row.keys():
                    base_row[c].append(new_row[c])
                    
                count_rows+=1
                
               
        processed_df = pd.DataFrame(base_row)
        processed_df['OUI'] = processed_df['OUI'].astype(str)
        processed_df['OUI'] = processed_df['OUI'].apply(oui_hex_to_float)
        # summary
        last_row = 0
        n_rows = 10
        df_summary_list = []
        while last_row < len(processed_df):
            sliced_df = processed_df[last_row:last_row + n_rows]
            mean_df = sliced_df.drop(columns=['Drone_port','OUI','Var_Payload']).mean().to_frame().T
            mode_dp_df = sliced_df['Drone_port'].mode()
            mode_oui_df=sliced_df['OUI'].mode()
            var_payload_length = sliced_df['Payload_Length'].var()

            mode_drone_port = mode_dp_df[0] if not mode_dp_df.empty else None
            mode_oui = mode_oui_df[0] if not mode_oui_df.empty else None
            mean_df.insert(loc=5, column='Drone_port', value=mode_drone_port)
            mean_df.insert(loc=6, column='OUI', value=mode_oui)
            mean_df.insert(loc=2, column='Var_Payload', value=var_payload_length)
            df_summary_list.append(mean_df)
            last_row += n_rows
        processed_df = pd.concat(df_summary_list).reset_index(drop=True)
        print("DataFrame list length:", len(df_summary_list))
        processed_df.to_csv(csv_file_name+".csv", index=False)
        return True
