#include <netinet/tcp.h>

typedef struct _tcp_head
{
    uint16_t tcp_src;
    uint16_t tcp_dst;
    uint32_t tcp_seq;
    uint32_t tcp_ackno;

#if __BYTE_ORDER__ == __LITTLE_ENDIAN
    uint8_t tcp_rsv1 : 4;
    uint8_t tcp_off : 4; // data offset, header length
    uint8_t tcp_fin : 1;
    uint8_t tcp_syn : 1;
    uint8_t tcp_rst : 1;
    uint8_t tcp_psh : 1;
    uint8_t tcp_ack : 1;
    uint8_t tcp_urg : 1;
    uint8_t tcp_rsv2 : 2;
#else
    uint8_t tcp_off : 4;
    uint8_t tcp_rsv1 : 4;
    uint8_t tcp_rsv2 : 2;
    uint8_t tcp_urg : 1;
    uint8_t tcp_ack : 1;
    uint8_t tcp_psh : 1;
    uint8_t tcp_rst : 1;
    uint8_t tcp_syn : 1;
    uint8_t tcp_fin : 1;
#endif
    uint16_t tcp_win_size;
    uint16_t tcp_checksum;
    uint16_t tcp_ugr_ptr;
} tcp_head;