#include <stdint.h>
//#define ETH_ALEN 6

typedef struct _ether_addr
{
    char eth_addr[6];
} ether_addr;

typedef struct _ether_head
{
    ether_addr eth_dest_addr;
    ether_addr eth_src_addr;
    uint16_t type;
} ether_head;
