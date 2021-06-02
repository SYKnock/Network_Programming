#include <stdint.h>
#include <endian.h>

#define DHCP_HLEN 236
#define DHCP_MAGIC_1 0x63
#define DHCP_MAGIC_2 0x82
#define DHCP_MAGIC_3 0x53
#define DHCP_MAGIC_4 0x63

typedef struct _dhcp_file
{
    char file[128];
} dhcp_file_;

typedef struct _dhcp_sname
{
    char sname[64];
} dhcp_sname_;

typedef struct _dhcp_chaddr
{
    char chaddr[16];
} dhcp_chaddr_;

typedef struct _dhcp_head
{
    uint8_t dhcp_op;
    uint8_t dhcp_htype;
    uint8_t dhcp_hlen;
    uint8_t dhcp_hops;
    uint32_t dhcp_xid;
    uint16_t dhcp_secs;
    uint16_t dhcp_flags;
    uint32_t dhcp_ciaddr;
    uint32_t dhcp_yiaddr;
    uint32_t dhcp_siaddr;
    uint32_t dhcp_giaddr;
    dhcp_chaddr_ dhcp_chaddr;
    dhcp_sname_ dhcp_sname;
    dhcp_file_ dhcp_file;
} dhcp_head;

enum
{
    padOption = 0,
    subnetMask = 1,
    timerOffset = 2,
    routersOnSubnet = 3,
    timeServer = 4,
    nameServer = 5,
    dns = 6,
    logServer = 7,
    cookieServer = 8,
    lprServer = 9,
    impressServer = 10,
    resourceLocationServer = 11,
    hostName = 12,
    domainName = 15,
    dhcpRequestedIPaddr = 50,
    dhcpIPaddrLeaseTime = 51,
    dhcpOptionOverload = 52,
    dhcpMessageType = 53,
    dhcpServerIdentifier = 54,
    dhcpParamRequest = 55,
    dhcpErrMsg = 56,
    dhcpMaxMsgSize = 57,
    dhcpRenewalTime = 58,
    dhcpRebindingTime = 59,
    dhcpClassIdentifier = 60,
    dhcpClientIdentifier = 61,
    dhcpClientFullyQualifiedDomainName = 81,
    domainSearchList = 119,
    endOption = 255
};