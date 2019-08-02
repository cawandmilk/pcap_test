#include <iostream>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <algorithm>
#include <arpa/inet.h>
#include "packet.h"

using namespace std;

void usage()
{
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int is_tcp_packet(const u_char* src, my_packet* dst, uint tot_len)
{
    // Initialize the packet if it is tcp protocol packet.
    memcpy(&(dst->e), src, sizeof(dst->e));

    // Set ip protocol if L3 is IP.
    if( ntohs(dst->e.ether_type) != ETHERTYPE_IP )
    {
        return 0;
    }
    memcpy(&(dst->i), &src[LIBNET_ETH_H], sizeof(dst->i));

    // Set tcp protocol if L4 is tcp.
    if( dst->i.ip_p != IPPROTO_TCP )
    {
        return 0;
    }
    memcpy(&(dst->t), &src[LIBNET_ETH_H + LIBNET_IPV4_H], sizeof(dst->t));

    // Set tcp data and the length.
    u_int data_start_index = LIBNET_ETH_H + LIBNET_IPV4_H + 4*(src[LIBNET_ETH_H + LIBNET_IPV4_H + 12] >> 4);
    dst->data_sz = (tot_len - data_start_index > 10 ? 10 : tot_len - data_start_index);
    memcpy(dst->data, &src[data_start_index], dst->data_sz);

    return 1;
}

void print_mac(const u_int8_t* mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X\t", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(in_addr ip)
{
    printf("%s\t", inet_ntoa(ip));
}

void print_port(uint16_t port)
{
    printf("%d\n", ntohs(port));
}

void print_packet(my_packet* p)
{
    printf("Source:\t\t");
    print_mac(p->e.ether_shost);    print_ip(p->i.ip_src);  print_port(p->t.th_sport);

    printf("Destination:\t");
    print_mac(p->e.ether_dhost);    print_ip(p->i.ip_dst);  print_port(p->t.th_dport);

    printf("Data:\t\t");
    for(unsigned long i = 0; i < p->data_sz; i++)
    {
        printf("%.2X ", p->data[i]);
    }
    if( p->data[0] == 0 )
    {
        printf("-");
    }
    printf("\n\n");
}
