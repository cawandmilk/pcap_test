#ifndef PACKET_H
#define PACKET_H

#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "./include/libnet/libnet-macros.h"
#include "./include/libnet/libnet-headers.h"

struct my_packet {
    struct libnet_ethernet_hdr e;
    struct libnet_ipv4_hdr i;
    struct libnet_tcp_hdr t;
    u_char data[10];
    unsigned long data_sz;
};

void usage();

void print_mac(const u_char* mac);
void print_ip(in_addr ip);
void print_port(uint16_t port);
void print_packet(my_packet* p);

int is_tcp_packet(const u_char* src, my_packet* dst, uint tot_len);

#endif // PACKET_H
