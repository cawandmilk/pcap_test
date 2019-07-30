#include <iostream>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <algorithm>
#include "packet.h"

using namespace std;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const u_int8_t* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\t", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(in_addr* ip) {
    printf("%u.%u.%u.%u\t", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(const u_int16_t* port) {
    printf("%d\n", (port[0] << 8) | port[1]);
}

void print_tcp_data(const u_char* packet, u_int data_len) {

    u_int i = ETHERNET_SIZE + IP_SIZE + 4 * (packet[TCP_SIZE_LOC] >> 4);    // 'i' is the first location of the tcp-data.
    for(int cnt = 0; (cnt < MAX_DATA_LENGTH) && (i < data_len); cnt++, i++) // Print the data(maximum 10 bytes).
        printf("%02X ", packet[i]);
    printf("\n");
}

bool is_ip_packet(const u_char* packet) {
    return ((packet[L2_TYPE] << 8) | packet[L2_TYPE + 1]) == IP;
}

bool is_tcp_packet(const u_char* packet) {
    return packet[L3_TYPE] == TCP;
}

void print_packet(const u_char* packet, struct pcap_pkthdr* header) {

    struct libnet_ethernet_hdr e;
    if ( !memcpy(&e, packet, sizeof(e)) ) {
         std::cout << "No Packet Accepted!" << std::endl;
         return;
    }

    if ( e.ether_type != LIBNET_IPV4_H ) return;

    struct libnet_ipv4_hdr i;
    if( !memcpy(&i, packet + LIBNET_ETH_H, sizeof(i)) ) {
        std::cout << "Invalid IPv4 Packet Accepted!" << std::endl;
        return;
    }

    if( i.ip_p != LIBNET_TCP_H ) return;

    struct libnet_tcp_hdr t;
    if( !memcpy(&t, packet + LIBNET_ETH_H + LIBNET_IPV4_H, sizeof(t))) {
        std::cout << "Invalid TCP Packet Accepted!" << std::endl;
        return;
    }

    std::cout << "Source:\t\t";
    print_mac(e.ether_shost); print_ip(&i.ip_src); print_port(&t.th_sport);

    std::cout << "Destination:\t";
    print_mac(e.ether_dhost); print_ip(&i.ip_dst); print_port(&t.th_dport);

    u_char* data = (header->caplen > i.ip_len ? const_cast<u_char*>(&packet[i.ip_len]) : NULL);
    u_int data_len = header->caplen - i.ip_len;

    if( !data )
        std::cout << "-" << std::endl;
    else
        for(u_int cnt = 0; (cnt < 10) && (cnt < data_len); cnt++ )
            std::cout << showbase << std::internal << data[cnt] << " ";
}
