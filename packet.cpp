#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "packet.h"

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const u_char* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const u_char* ip) {
    printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(const u_char* port) {
    printf("%d\n", (port[0] << sizeof(u_char)) | port[1]);
}

void print_tcp_data(const u_char* packet, u_int data_len) {
    for( u_int cnt = 0, i = 0; (i < data_len) && (cnt < MAX_DATA_LENGTH); i++, cnt++)
        printf("%02X ", packet[i]);
    printf("\n");
}

bool is_ip_packet(const u_char* packet) {
    return ((packet[0] << 8) | packet[1]) == IP;
}

bool is_tcp_packet(const u_char* packet) {
    return packet[0] == TCP;
}

void print_tcp_packet(const u_char* packet, struct pcap_pkthdr* header) {

    if( !is_ip_packet(&packet[L2_TYPE]) || !is_tcp_packet(&packet[L3_TYPE]) )
        return;

    printf("Smac : ");      print_mac(&packet[SMAC_LOC]);
    printf("Dmac : ");      print_mac(&packet[DMAC_LOC]);
    printf("Sip  : ");      print_ip(&packet[SIP_LOC]);
    printf("Dip  : ");      print_ip(&packet[DIP_LOC]);
    printf("Sport: ");      print_port(&packet[SPORT_LOC]);
    printf("Dport: ");      print_port(&packet[DPORT_LOC]);

    printf("Data : ");
    print_tcp_data(&packet[ETHERNET_SIZE + IP_SIZE + (packet[TCP_SIZE_LOC] >> 4)], header->caplen);

    printf("\n");
}
