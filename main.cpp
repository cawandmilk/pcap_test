#include <pcap.h>
#include <stdio.h>
#include "packet.h"


int main(int argc, char* argv[])
{
  if (argc != 2)
  {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL)
  {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    struct my_packet *p = (my_packet*)calloc(1, sizeof(my_packet));
    if( is_tcp_packet(packet, p, header->caplen) )
    {
        print_packet(p);
    }
    free(p);
  }

  pcap_close(handle);
  return 0;
}
