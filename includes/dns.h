#include <stdint.h>
#include <endian.h>

#define DNS_HLEN 12

typedef struct _dns_head
{
    uint16_t dns_id;
#if __BYTE_ORDER__ == __LITTLE_ENDIAN
    uint8_t dns_rd : 1;
    uint8_t dns_tc : 1;
    uint8_t dns_aa : 1;
    uint8_t dns_opcode : 4;
    uint8_t dns_qr : 1;
    uint8_t dns_rcode : 4;
    uint8_t dns_z : 3;
    uint8_t dns_ra : 1;
#else
    uint8_t dns_qr : 1;
    uint8_t dns_opcode : 4;
    uint8_t dns_aa : 1;
    uint8_t dns_tc : 1;
    uint8_t dns_rd : 1;
    uint8_t dns_ra : 1;
    uint8_t dns_z : 3;
    uint8_t dns_rcode : 4;
#endif
    uint16_t dns_qdc;
    uint16_t dns_anc;
    uint16_t dns_nsc;
    uint16_t dns_arc;
}dns_head;