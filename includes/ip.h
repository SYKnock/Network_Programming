#include <netinet/ip.h>

#define IPHRD_SIZE 20

typedef struct _ip_head
{
#if __BYTE_ORDER__ == __LITTLE_ENDIAN
    uint8_t ip_hdr_len : 4;
    uint8_t ip_version : 4;
#else
    uint8_t ip_version : 4;
    uint8_t ip_hdr_len : 4;
#endif
    uint8_t ip_tos;
    uint16_t ip_tot_len;
    uint16_t ip_id;
    uint16_t ip_flag_off; // flag + fragment offset
    uint8_t ip_ttl;
    uint8_t ip_protocol;
    uint16_t ip_checksum;
    uint32_t ip_src;
    uint32_t ip_dst;
} ip_head;
