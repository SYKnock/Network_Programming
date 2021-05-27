#include <netinet/udp.h>

#define UDP_HLEN 8

typedef struct _udp_head
{
    uint16_t udp_src;
    uint16_t udp_dst;

    uint16_t udp_len;
    uint16_t udp_checksum;
}udp_head;
