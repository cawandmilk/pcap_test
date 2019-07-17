#ifndef PACKET_H
#define PACKET_H

#include <pcap.h>

#define MAX_DATA_LENGTH 10

#define ETHERNET_SIZE 14
#define IP_SIZE 20

enum PACKET_LOCATION { DMAC_LOC = 0, SMAC_LOC = 6,
                       SIP_LOC = 26, DIP_LOC = 30,
                       SPORT_LOC = 34, DPORT_LOC = 36, TCP_SIZE_LOC = 46};
enum LAYER_TYPE { L2_TYPE = 12, L3_TYPE = 24 };
enum L2_PROTOCOL { IP = 0x0800, ARP = 0x0806, IPv6 = 0x86DD };
enum L3_PROTOCOL { ICMP = 0x01, TCP = 0x06, UDP = 0x11 };

void usage();

void print_mac(const u_char* mac);
void print_ip(const u_char* ip);
void print_port(const u_char* port);
void print_tcp_data(const u_char* packet, u_int data_len);
bool is_ip_packet(const u_char* packet);
bool is_tcp_packet(const u_char* packet);

void print_tcp_packet(const u_char* packet, struct pcap_pkthdr* header);

#endif // PACKET_H
