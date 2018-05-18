#!/usr/bin/python

import sys
import pyshark
from collections import OrderedDict
import argparse
from decimal import Decimal

class PacketStat():
    flow_count = 5
    flow_time = 1
    def __init__(self, filename, outfile, count, time):
        self.packets = []
        self.cap = pyshark.FileCapture(filename, keep_packets=False)
        self.outfile = open(outfile, 'w')
        
        def find_tcp_udp(*args):
            if hasattr(args[0], 'tcp'):
                self.packets.append(args[0])
            elif hasattr(args[0], 'udp'):
                self.packets.append(args[0])

        self.cap.apply_on_packets(find_tcp_udp)

        self.packets_len = len(self.packets)

        print("Source IP, Dest IP, Source Port, Dest Port," + \
              "source mac, dest mac, Duration, Total Bytes," + \
              "Total Pkts, FlowsCount, TCPCount, UDPCount," + \
              "AvgBytes, AvgPkts, AvgTCPpkts, AvgUDPpkts," + \
              "FIN,SYN,RESET,PSH,ACK,URG," + \
              "ECN,CWR,NS,RES",  file=self.outfile)

        if args.count is not None:
            PacketStat.flow_count = count
            self.process_packets_count()
        else:
            PacketStat.flow_time = time
            self.process_packets_time()

    def __del__(self):
        self.outfile.close()


    def process_packets_count(self):
        for start in range(0, self.packets_len, PacketStat.flow_count):
            pkt_group = self.packets[start:start+PacketStat.flow_count]
            #print(start)
            self.process_group(pkt_group)


    def process_packets_time(self):
        ts = 0.0
        pkt_group = []
        for pkt in self.packets:
            pkt_ts = float(pkt.sniff_timestamp)
            if round(Decimal(pkt_ts) - Decimal(ts), 6) > Decimal(PacketStat.flow_time):
                self.process_group(pkt_group)
                pkt_group = []
                ts = pkt_ts
                #print("Process Group")
            pkt_group.append(pkt)
            
            
            
    def process_group(self, pkt_group):
        stat_dict = OrderedDict()
        for pkt in pkt_group:
            if hasattr(pkt, 'ipv6'):
                src_ip = pkt.ipv6.src
                dst_ip = pkt.ipv6.dst
            else:
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst

            key = src_ip + '-' + dst_ip

            if stat_dict.get(key) != None:
                statRow = stat_dict[key]
                statRow.update(pkt)
                
            else:
                statRow = StatRow(src_ip, dst_ip, pkt)
                stat_dict[key] = statRow

        self.write_file( stat_dict)

    def write_file(self, stat_dict):
        for row in stat_dict.values():
            #print(row, file=self.outfile, flush=True)
            #print(row)
            print(row, file=self.outfile)
        
class StatRow():
    def __init__(self, src_ip, dst_ip, pkt):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.tcp_count = 0
        self.udp_count = 0
        proto = 'udp'
        if hasattr(pkt, 'tcp'):
            self.tcp_count += 1
            proto = 'tcp'
        elif hasattr(pkt, 'udp'):
            self.udp_count += 1
        self.src_port = pkt[proto].srcport
        self.dst_port = pkt[proto].dstport
        self.src_mac = ""
        self.dst_mac = ""
        if hasattr(pkt, 'eth'):
            self.src_mac = pkt.eth.src
            self.dst_mac = pkt.eth.dst
        
        self.time1 = float(pkt.sniff_timestamp)#pkt.sniff_time
        self.time2 = float(pkt.sniff_timestamp)#pkt.sniff_time
        #self.time_diff = round(Decimal(self.time1) - Decimal(self.time2), 6)
        self.time_diff = 0.0
        self.total_bytes = int(pkt.captured_length)
        self.total_pkts = 1

        self.avg_bytes = 0.0
        self.avg_pkts = 0.0
        self.avg_tcppkts = 0.0
        self.avg_udppkts = 0.0

        #TCP FLAGS
        self.flag_fin = "0"
        self.flag_syn = "0"
        self.flag_reset = "0"
        self.flag_psh = "0"
        self.flag_ack = "0"
        self.flag_urg = "0"
        self.flag_ecn = "0"
        self.flag_cwr = "0"
        self.flag_ns = "0"
        self.flag_res = "0"
        
        self.average_cal()
        self.update_tcp_flags(pkt, False)

    def update(self, pkt):
        proto = 'udp'
        if hasattr(pkt, 'tcp'):
            self.tcp_count += 1
            proto = 'tcp'
        elif hasattr(pkt, 'udp'):
            self.udp_count += 1
        self.total_bytes += int(pkt.captured_length)
        #print (self.total_bytes)
        self.total_pkts += 1
        self.time1 = float(pkt.sniff_timestamp)
        self.time_diff = round(Decimal(self.time1) - Decimal(self.time2), 6)
        self.average_cal()
        self.update_tcp_flags(pkt, True)
        
    def update_tcp_flags(self, pkt, flag):
        if hasattr(pkt, 'udp'):
            return
        '''
        if pkt.tcp.flags_fin == '1':
            self.flag_fin = 'FIN'
        if pkt.tcp.flags_syn == '1':
            self.flag_syn = 'SYN'
        if pkt.tcp.flags_reset == '1':
            self.flag_reset = 'RESET'
        if pkt.tcp.flags_push == '1':
            self.flag_psh = 'PSH'
        if pkt.tcp.flags_ack == '1':
            self.flag_ack = 'ACK'
        if pkt.tcp.flags_urg == '1':
            self.flag_urg = 'URG'
        if pkt.tcp.flags_ecn == '1':
            self.flag_ecn = 'ECN'
        if pkt.tcp.flags_cwr == '1':
            self.flag_cwr = 'CWR'
        if pkt.tcp.flags_ns == '1':
            self.flag_ns = 'NS'
        if pkt.tcp.flags_res != '0':
            self.flag_res = 'RES'
            '''
        if flag:
            self.flag_fin += '|' + pkt.tcp.flags_fin
            self.flag_syn += '|' +  pkt.tcp.flags_syn
            self.flag_reset += '|' + pkt.tcp.flags_reset
            self.flag_psh += '|' + pkt.tcp.flags_push
            self.flag_ack += '|' + pkt.tcp.flags_ack
            self.flag_urg += '|' + pkt.tcp.flags_urg
            self.flag_ecn += '|' + pkt.tcp.flags_ecn
            self.flag_cwr += '|' + pkt.tcp.flags_cwr
            self.flag_ns += '|' + pkt.tcp.flags_ns
            self.flag_res += '|' + pkt.tcp.flags_res
        else:
            self.flag_fin = pkt.tcp.flags_fin
            self.flag_syn = pkt.tcp.flags_syn
            self.flag_reset = pkt.tcp.flags_reset
            self.flag_psh = pkt.tcp.flags_push
            self.flag_ack = pkt.tcp.flags_ack
            self.flag_urg = pkt.tcp.flags_urg
            self.flag_ecn = pkt.tcp.flags_ecn
            self.flag_cwr = pkt.tcp.flags_cwr
            self.flag_ns = pkt.tcp.flags_ns
            self.flag_res = pkt.tcp.flags_res
     

    def average_cal(self):
        '''self.avg_pkts = self.total_pkts / PacketStat.flow_count
        self.avg_tcppkts = self.tcp_count / PacketStat.flow_count
        self.avg_udppkts = self.udp_count / PacketStat.flow_count
        self.avg_bytes = self.total_bytes / PacketStat.flow_count'''
        self.avg_pkts = self.total_pkts / PacketStat.flow_count
        self.avg_tcppkts = self.tcp_count / self.total_pkts
        self.avg_udppkts = self.udp_count / self.total_pkts
        self.avg_bytes = self.total_bytes / self.total_pkts
        
        
    def __str__(self):

        return "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}".format(self.src_ip, self.dst_ip, self.src_port, self.dst_port,
                                                   self.src_mac, self.dst_mac, self.time_diff, self.total_bytes,
                                                   self.total_pkts, PacketStat.flow_count, self.tcp_count, self.udp_count,
                                                   self.avg_bytes, self.avg_pkts, self.avg_tcppkts, self.avg_udppkts,
                                                   self.flag_fin, self.flag_syn, self.flag_reset, self.flag_psh,
                                                   self.flag_ack, self.flag_urg, self.flag_ecn, self.flag_cwr,
                                                   self.flag_ns,  self.flag_res                                                  
                                                   )
    def string(self):
        return self.__str__()


class AllPacket():

    def __init__(self, filename, outfile):
        self.packets = []
        self.cap = pyshark.FileCapture(filename, keep_packets=False)
        self.outfile = open(outfile, 'w')

        self.pre_ts = 0.0
        self.flag = True

        def find_tcp_udp(*args):

            if hasattr(args[0], 'tcp'):
                self.packets.append(args[0])
                self.flag = False
            elif hasattr(args[0], 'udp'):
                self.packets.append(args[0])
                self.flag = False
            else:
                if self.flag:
                    self.pre_ts = float(args[0].sniff_timestamp)

        self.cap.apply_on_packets(find_tcp_udp)

        self.packets_len = len(self.packets)

        print("Source IP, Dest IP, Source Port, Dest Port," + \
              "source mac, dest mac, Duration, Bytes," + \
              "Protocol, FIN, SYN, RESET, " + \
              "PSH, ACK, URG," + \
              "ECN, CWR, NS, RES",  file=self.outfile)

        self.process_packets()

    def __del__(self):
        self.outfile.close()        

    def process_packets(self):
        for pkt in self.packets:
            src_ip = ""
            dst_ip = ""
            if hasattr(pkt, 'ipv6'):
                src_ip = pkt.ipv6.src
                dst_ip = pkt.ipv6.dst
            else:
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst

            proto = 'udp'

            flag_fin = '0'
            flag_syn = '0'
            flag_reset = '0'
            flag_psh = '0'
            flag_ack = '0'
            flag_urg = '0'
            flag_ecn = '0'
            flag_cwr = '0'
            flag_ns = '0'
            flag_res = '0'

            if hasattr(pkt, 'tcp'):
                proto = 'tcp'
                '''if pkt.tcp.flags_fin == '1':
                    flag_fin = 'FIN'
                if pkt.tcp.flags_syn == '1':
                    flag_syn = 'SYN'
                if pkt.tcp.flags_reset == '1':
                    flag_reset = 'RESET'
                if pkt.tcp.flags_push == '1':
                    flag_psh = 'PSH'
                if pkt.tcp.flags_ack == '1':
                    flag_ack = 'ACK'
                if pkt.tcp.flags_urg == '1':
                    flag_urg = 'URG'
                if pkt.tcp.flags_ecn == '1':
                    flag_ecn = 'ECN'
                if pkt.tcp.flags_cwr == '1':
                    flag_cwr = 'CWR'
                if pkt.tcp.flags_ns == '1':
                    flag_ns = 'NS'
                if pkt.tcp.flags_res != '0':
                    flag_res = 'RES'
                    '''

                flag_fin = pkt.tcp.flags_fin
                flag_syn = pkt.tcp.flags_syn
                flag_reset = pkt.tcp.flags_reset
                flag_psh = pkt.tcp.flags_push
                flag_ack = pkt.tcp.flags_ack
                flag_urg = pkt.tcp.flags_urg
                flag_ecn = pkt.tcp.flags_ecn
                flag_cwr = pkt.tcp.flags_cwr
                flag_ns = pkt.tcp.flags_ns
                flag_res = pkt.tcp.flags_res

            src_port = pkt[proto].srcport
            dst_port = pkt[proto].dstport
            src_mac = ""
            dst_mac = ""
            if hasattr(pkt, 'eth'):
                src_mac = pkt.eth.src
                dst_mac = pkt.eth.dst

            ts = float(pkt.sniff_timestamp)

            duration = round(Decimal(ts) - Decimal(self.pre_ts), 6)
            self.pre_ts = ts
            
            byte = pkt.captured_length

            print_str = "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}".format(src_ip, dst_ip, src_port, dst_port,
                                                   src_mac, dst_mac, duration, byte, proto,
                                                   flag_fin, flag_syn, flag_reset, flag_psh,
                                                   flag_ack, flag_urg, flag_ecn, flag_cwr,
                                                   flag_ns,  flag_res                                                  
                                                   )
            print(print_str, file=self.outfile)
            
#main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Network Statistics Analyzer.')
    group = parser.add_mutually_exclusive_group(required=True)
    #parser.add_argument('--count', help='Flow Count', type=int, default=5)
    group.add_argument('--count', help='Group packets based on count', type=int)
    group.add_argument('--all', help='All packets', action='store_true')
    group.add_argument('--time', help='Group packets based on time(seconds)', type=int)
    parser.add_argument('--pcap', help='PCAP file', type=str, required=True)
    parser.add_argument('--out', help='Output file', type=str, default='output.csv')
    args = parser.parse_args()

    #PacketStat('sample2.pcap')
    if args.all:
        AllPacket(args.pcap, args.out)
    else :
        PacketStat(args.pcap, args.out, args.count, args.time)
