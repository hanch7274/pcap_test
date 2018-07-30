#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>
#define ETH_SIZE 14

//https://code.woboq.org/userspace/glibc/sysdeps/generic/netinet/ip.h.html

void print_eth(const uint8_t *packet);
void print_ip(const uint8_t *packet);
void print_tcp(const uint8_t *packet,int IP_SIZE);
void print_data(const uint8_t *packet, int IP_SIZE, int TCP_SIZE);

struct ip *h_ip;
struct tcphdr *h_tcp;
struct ether_header *h_eth;

void print_eth(const uint8_t *packet)
{
  h_eth = (struct ether_header *)packet;
  printf("src_mac : ");
  for(int i=0; i<ETH_ALEN;i++)
    printf("%02x:", h_eth->ether_shost[i]);
  printf("\b\n");
  printf("dst_mac : ");
  for(int i=0; i<ETH_ALEN;i++)
    printf("%02x:", h_eth->ether_dhost[i]);
  printf("\b\n");

  if(ntohs(h_eth->ether_type)==ETHERTYPE_IP)
    print_ip(packet);
}
void print_ip(const uint8_t *packet)
{
  h_ip = (struct ip *)(packet + ETH_SIZE);

  char src_ip[16],dst_ip[16];
  inet_ntop(AF_INET, &(h_ip->ip_src),src_ip,16);
  printf("src_ip : %s\n", src_ip);
  inet_ntop(AF_INET, &(h_ip->ip_dst),dst_ip,16);
  printf("dst_ip : %s\n", dst_ip);

  if(h_ip->ip_p == IPPROTO_TCP)
  {
    int IP_SIZE = h_ip->ip_hl * 4;
    print_tcp(packet,IP_SIZE);
  }
}
void print_tcp(const uint8_t *packet,int IP_SIZE)
{
  h_tcp = (struct tcphdr *)(packet + ETH_SIZE + IP_SIZE);
  int TCP_SIZE = h_tcp->th_off*4;
  printf("src_port : %d\n", ntohs(h_tcp->th_sport));
  printf("dst_port : %d\n", ntohs(h_tcp->th_dport));
  print_data(packet,IP_SIZE,TCP_SIZE);
}

void print_data(const uint8_t *packet, int IP_SIZE, int TCP_SIZE)
{
  char data[17];
  printf("Data : %s\n", memcpy(data, (char*)packet + ETH_SIZE +IP_SIZE + TCP_SIZE,16));
}
void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("%u bytes captured\n", header->caplen);
    print_eth(packet);
    printf("===============================\n");
  }

  pcap_close(handle);
  return 0;
}
