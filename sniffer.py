import socket
import struct
#import os
#import scapy


def ethernet_frame(data):
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(protocol), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

#ip header
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, protocol, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_module(data):
    (src_port_tcp, dest_port_tcp, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port_tcp, dest_port_tcp, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_module(data):
    src_port_udp, dest_port_udp, size = struct.unpack('! H H 2x H', data[:8])
    return src_port_udp, dest_port_udp, size, data[8:]
def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    counter = 0

    print ('\nIP Header Information:\n')
    print ('Destination MAC\t    Source MAC\t\tSource IP\tDestination IP\tSource Port\tDestination Port    Time to Live   Flag\t   Packet length')
    while True:
        raw_data, addr = connection.recvfrom(65535)
        dest_mac, src_mac, eth_protocol, data = ethernet_frame(raw_data)
        (version, header_length, ttl, protocol, src, target, data) = ipv4_packet(data)
        (src_port_tcp, dest_port_tcp, sequence, acknowledgement, flag_urg, flag_ack, flag_psh,
        flag_rst, flag_syn, flag_fin, data) = tcp_module(raw_data)


        flag_type = ''
        if flag_urg==1:
            flag_type = ('URG')
        elif flag_ack==1:
            flag_type = ('ACK')
        elif flag_psh==1:
            flag_type = ('PSH')
        elif flag_rst==1:
            flag_type = ('RST')
        elif flag_syn==1:
            flag_type = ('SYN')
        elif flag_fin==1:
            flag_type = ('FIN')

        else:
            flag_type = ''

        flag_type2 = ''
        if (flag_urg==1) and (flag_type!='URG'):
            flag_type2 = (',URG')
        elif (flag_ack==1) and (flag_type!='ACK'):
            flag_type2 = (',ACK')
        elif (flag_psh==1) and (flag_type!='PSH'):
            flag_type2 = (',PSH')
        elif (flag_rst==1) and (flag_type!='RST'):
            flag_type2 = (',RST')
        elif (flag_syn==1) and (flag_type!='SYN'):
            flag_type2 = (',SYN')
        elif (flag_fin==1) and (flag_type!='FIN'):
            flag_type2 = (',FIN')

        else:
            flag_type2 = ''

        #print (dest_mac + '   ' + src_mac + '\t' + src + '\t' + target + '\t' + format(src_port_tcp) + '\t\t' + format(dest_port_tcp) + '\t\t    ' + format(ttl) + '\t\t   ' + flag_type + flag_type2 + '\t\t' + format(len(data)))
       
        counter = counter+1
        if counter %== 10:
            print(counter)
main()