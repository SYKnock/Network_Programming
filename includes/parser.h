#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#include "arp.h"
#include "dns.h"
#include "http.h"
#include "https.h"
#include "dhcp.h"
#include "ether.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"

void ether_parser(char *buff, ether_head *eth, FILE *fp);
void ipv4_parser(char *buff, ip_head *ip, FILE *fp, int byte);
void tcp_parser(char *buff, tcp_head *tcp, FILE *fp);
void udp_parser(char *buff, udp_head *udp, FILE *fp);
void arp_parser(char *buff, arp_head *arp, FILE *fp);
void dns_parser(char *buff, FILE *fp);
void http_parser(char *buff, FILE *fp);
void https_parser(char *buff, FILE *fp);
void dhcp_parser(char *buff, FILE *fp);
void dump_mem(const void *mem, size_t len, FILE *fp);

void ether_parser(char *buff, ether_head *eth, FILE *fp)
{
    fprintf(fp, "===============================================\n");
    fprintf(fp, "Ethernet\n");
    fprintf(fp, "Destination: ");
    for (int i = 0; i < ETH_ALEN; i++)
    {
        fprintf(fp, "%02hhx", eth->eth_dest_addr.eth_addr[i] & 0xff);
        if (i != ETH_ALEN - 1)
            fprintf(fp, ":");
    }
    if (strncmp("ffffffffffff", eth->eth_dest_addr.eth_addr, 12))
        fprintf(fp, "(Broadcast)\n");

    fprintf(fp, "Source: ");
    for (int i = 0; i < ETH_ALEN; i++)
    {
        fprintf(fp, "%02hhx", eth->eth_src_addr.eth_addr[i] & 0xff);
        if (i != ETH_ALEN - 1)
            fprintf(fp, ":");
    }
    fprintf(fp, "\n");

    fprintf(fp, "Type: ");
    if (ntohs(eth->type) == ETH_P_ARP)
        fprintf(fp, "ARP (0x%04x)", eth->type);
    else if (ntohs(eth->type) == ETH_P_IP)
        fprintf(fp, "IPv4 (0x%04x)", eth->type);
    else
        fprintf(fp, "Others (0x%04x)", eth->type);
    fprintf(fp, "\n");
}

void ipv4_parser(char *buff, ip_head *ip, FILE *fp, int byte)
{
    printf("IP detect. Captured byte: %d\n", byte);
    fprintf(fp, "-----------------------------------------------\n");
    fprintf(fp, "IPv4 protocol\n");
    fprintf(fp, "Version: %d\n", ip->ip_version);
    fprintf(fp, "Header Length: %d bytes (%d)\n", ip->ip_hdr_len * 4, ip->ip_hdr_len);
    fprintf(fp, "Type Of Servie: 0x%02hhx\n", ip->ip_tos & 0xff);
    fprintf(fp, "Total Length: %d\n", ntohs(ip->ip_tot_len));
    fprintf(fp, "Identification: 0x%04x (%d)\n", ntohs(ip->ip_id), ntohs(ip->ip_id));
    fprintf(fp, "Flags: 0x%04x, ", ntohs(ip->ip_flag_off));
    if ((ntohs(ip->ip_flag_off) & 0x4000) != 0)
        fprintf(fp, "Do not fragment\n");
    else if ((ntohs(ip->ip_flag_off) & 0x2000) != 0)
        fprintf(fp, "More fragment\n");
    fprintf(fp, "Fragment Offset: %d\n", ntohs(ip->ip_flag_off) & 0x1fff);
    fprintf(fp, "Time to Live: %d\n", ip->ip_ttl);
    if (ip->ip_protocol == IPPROTO_TCP)
        fprintf(fp, "Protocol: TCP (%d)\n", IPPROTO_TCP);
    else if (ip->ip_protocol == IPPROTO_UDP)
        fprintf(fp, "Protocol: UDP (%d)\n", IPPROTO_UDP);
    else
        fprintf(fp, "Protocol: Others (%d)", ip->ip_protocol);

    fprintf(fp, "Header Checksum: 0x%04x\n", ntohs(ip->ip_checksum));

    fprintf(fp, "Source: %d.%d.%d.%d\n", ip->ip_src & 0xff, (ip->ip_src >> 8) & 0xff, (ip->ip_src >> 16) & 0xff, (ip->ip_src >> 24) & 0xff);
    fprintf(fp, "Destination: %d.%d.%d.%d\n", ip->ip_dst & 0xff, (ip->ip_dst >> 8) & 0xff, (ip->ip_dst >> 16) & 0xff, (ip->ip_dst >> 24) & 0xff);
}

void tcp_parser(char *buff, tcp_head *tcp, FILE *fp)
{
}

void udp_parser(char *buff, udp_head *udp, FILE *fp)
{
}

void arp_parser(char *buff, arp_head *arp, FILE *fp)
{
    memcpy(arp, buff + ETH_HLEN, ARP_HLEN);

    printf("ARP ");
    if (ntohs(arp->arp_op) == ARPOP_REPLY)
        printf("reply");
    else if (ntohs(arp->arp_op) == ARPOP_REQUEST)
        printf("request");
    else if (ntohs(arp->arp_op) == ARPOP_NAK)
        printf("NAK");
    else if (ntohs(arp->arp_op) == ARPOP_InREPLY)
        printf("in reply");
    else if (ntohs(arp->arp_op) == ARPOP_InREQUEST)
        printf("in request");
    else if (ntohs(arp->arp_op) == ARPOP_RREPLY)
        printf("re reply");
    else if (ntohs(arp->arp_op) == ARPOP_RREQUEST)
        printf("re request");
    printf(" detect: ");

    if (ntohs(arp->arp_op) == ARPOP_REPLY)
    {
        for (int i = 0; i < ARP_IP; i++)
        {
            printf("%d", arp->arp_src_ip.prt_addr[i]);
            if (i != ARP_IP - 1)
                printf(".");
        }
        printf(" is at ");
        for (int i = 0; i < ARP_MAC; i++)
        {
            printf("%02hhx", arp->arp_src_mac.hw_addr[i] & 0xff);
            if (i != ARP_MAC - 1)
                printf(":");
        }
    }
    else if (ntohs(arp->arp_op) == ARPOP_REQUEST)
    {
        printf("Who has ");
        for (int i = 0; i < ARP_IP; i++)
        {
            printf("%d", arp->arp_dest_ip.prt_addr[i]);
            if (i != ARP_IP - 1)
                printf(".");
        }
        printf(" Tell ");
        for (int i = 0; i < ARP_IP; i++)
        {
            printf("%d", arp->arp_src_ip.prt_addr[i]);
            if (i != ARP_IP - 1)
                printf(".");
        }
    }
    printf(" Captured byte: %d\n", ARP_HLEN + ETH_HLEN);

    fprintf(fp, "-----------------------------------------------\n");
    fprintf(fp, "Address Resolution Protocol(ARP)\n");

    fprintf(fp, "Hardware type: ");
    if (ntohs(arp->arp_hw_type) == ARPHRD_ETHER)
        fprintf(fp, "Ethernet (0x%04x)\n", ntohs(arp->arp_hw_type));
    else
        fprintf(fp, "Others (0x%04x)\n", ntohs(arp->arp_hw_type));

    fprintf(fp, "Protocol type: ");
    if (ntohs(arp->arp_proto_type) == 0x0800)
        fprintf(fp, "IPv4 (0x%04x)\n", ntohs(arp->arp_proto_type));
    else
        fprintf(fp, "Others (0x%04x)\n", ntohs(arp->arp_proto_type));

    fprintf(fp, "Hardware size: %d\n", arp->arp_hw_len);
    fprintf(fp, "Protocol size: %d\n", arp->arp_proto_len);

    fprintf(fp, "Opcode: ");
    if (ntohs(arp->arp_op) == ARPOP_REPLY)
        fprintf(fp, "reply (0x%04x)\n", ntohs(arp->arp_op));
    else if (ntohs(arp->arp_op) == ARPOP_REQUEST)
        fprintf(fp, "request (0x%04x)\n", ntohs(arp->arp_op));
    else if (ntohs(arp->arp_op) == ARPOP_NAK)
        fprintf(fp, "NAK (0x%04x)\n", ntohs(arp->arp_op));
    else if (ntohs(arp->arp_op) == ARPOP_InREPLY)
        fprintf(fp, "in reply (0x%04x)\n", ntohs(arp->arp_op));
    else if (ntohs(arp->arp_op) == ARPOP_InREQUEST)
        fprintf(fp, "in request (0x%04x)\n", ntohs(arp->arp_op));
    else if (ntohs(arp->arp_op) == ARPOP_RREPLY)
        fprintf(fp, "re reply (0x%04x)\n", ntohs(arp->arp_op));
    else if (ntohs(arp->arp_op) == ARPOP_RREQUEST)
        fprintf(fp, "re request (0x%04x)\n", ntohs(arp->arp_op));

    fprintf(fp, "Sender MAC address: ");
    for (int i = 0; i < ARP_MAC; i++)
    {
        fprintf(fp, "%02hhx", arp->arp_src_mac.hw_addr[i] & 0xff);
        if (i != ARP_MAC - 1)
            fprintf(fp, ":");
    }
    fprintf(fp, "\n");

    fprintf(fp, "Sender IP address: ");
    for (int i = 0; i < ARP_IP; i++)
    {
        fprintf(fp, "%d", arp->arp_src_ip.prt_addr[i]);
        if (i != ARP_IP - 1)
            fprintf(fp, ".");
    }
    fprintf(fp, "\n");

    fprintf(fp, "Target MAC address: ");
    for (int i = 0; i < ARP_MAC; i++)
    {
        fprintf(fp, "%02hhx", arp->arp_dest_mac.hw_addr[i] & 0xff);
        if (i != ARP_MAC - 1)
            fprintf(fp, ":");
    }
    fprintf(fp, "\n");

    fprintf(fp, "Target IP address: ");
    for (int i = 0; i < ARP_IP; i++)
    {
        fprintf(fp, "%d", arp->arp_dest_ip.prt_addr[i]);
        if (i != ARP_IP - 1)
            fprintf(fp, ".");
    }
    fprintf(fp, "\n");
    fprintf(fp, "Captured byte : %d\n", ARP_HLEN + ETH_HLEN);

    dump_mem(buff, ETH_HLEN + ARP_HLEN, fp);
}

void dns_parser(char *buff, FILE *fp)
{
}

void http_parser(char *buff, FILE *fp)
{
}

void https_parser(char *buff, FILE *fp)
{
}

void dhcp_parser(char *buff, FILE *fp)
{
}

void dump_mem(const void *mem, size_t len, FILE *fp)
{
    fprintf(fp, "\nMemory\n");
    const char *buffer = mem;
    size_t i;
    for (i = 0; i < len; i++)
    {
        if (i > 0 && i % 16 == 0)
        {
            fprintf(fp, "\n");
        }
        fprintf(fp, "%02x ", buffer[i] & 0xff);
    }
    fprintf(fp, "\n===============================================\n");
    fprintf(fp, "\n\n");
}
