#include <iostream>
#include <pcap.h>
#include <stdlib.h>
#include "packet.h"

using namespace std;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const u_char* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\t", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const u_char* ip) {
    printf("%u.%u.%u.%u\t", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(const u_char* port) {
    printf("%d\n", (port[0] << 8) | port[1]);
}

void print_tcp_data(const u_char* packet, u_int data_len) {
    if(!(packet[TCP_FLAG_LOC] & 0x08)) {  // The packet will have some data if PSH flag is '1'.
        printf("-\n");                    // 0x08 = 0b 0000 1000, 5th bit from MSB is PSH flag.
        return;
    }

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

    if( !is_ip_packet(packet) || !is_tcp_packet(packet) )   return;

    printf("Source:\t\t");
    print_mac(&packet[SMAC_LOC]);
    print_ip(&packet[SIP_LOC]);
    print_port(&packet[SPORT_LOC]);

    printf("Destination:\t");
    print_mac(&packet[DMAC_LOC]);
    print_ip(&packet[DIP_LOC]);
    print_port(&packet[DPORT_LOC]);

    printf("Data:\t\t");
    print_tcp_data(packet, header->caplen);

    printf("\n");
}
