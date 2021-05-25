#include <stdint.h>

#define ARP_HLEN 28
#define ARP_MAC 6
#define ARP_IP 4

typedef struct _arp_mac
{
    unsigned char hw_addr[6];
}arp_mac;

typedef struct _arp_ip
{
    unsigned char prt_addr[4];
}arp_ip;

typedef struct _arp_head
{
    uint16_t arp_hw_type;
    uint16_t arp_proto_type;
    uint8_t arp_hw_len;
    uint8_t arp_proto_len;
    uint16_t arp_op;
    arp_mac arp_src_mac;
    arp_ip arp_src_ip;
    arp_mac arp_dest_mac;
    arp_ip arp_dest_ip;
}arp_head;