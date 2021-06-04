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
#include "https.h"
#include "dhcp.h"
#include "ether.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"

#define HTTP_REQUEST 100
#define HTTP_RESPONSE 101

void ether_parser(char *buff, ether_head *eth, FILE *fp);
void ipv4_parser(char *buff, ip_head *ip, FILE *fp, int byte);
void tcp_parser(char *buff, tcp_head *tcp, FILE *fp);
void udp_parser(char *buff, udp_head *udp, FILE *fp);
void arp_parser(char *buff, arp_head *arp, FILE *fp);
void dns_parser(char *buff, dns_head *dns, FILE *fp, int dns_byte, int offset);
void http_parser(char *buff, unsigned char *http_buff, int http_length, FILE *fp, int r_flag, int c_byte);
void https_parser(char *buff, FILE *fp);
void dhcp_parser(char *buff, dhcp_head *dhcp, FILE *fp, int offset);
void dump_mem(const void *mem, size_t len, FILE *fp);
void dhcp_option_parser(char *buff, dhcp_head *dhcp, int offset, FILE *fp, char *dhcp_option);

unsigned char *dns_print_name(unsigned char *msg, unsigned char *pointer, unsigned char *end, FILE *fp);
unsigned char *dns_query(unsigned char *dns_buf, unsigned char *dns_message_buff, unsigned char *dns_buff_end, FILE *fp);
unsigned char *dns_answer(unsigned char *dns_buff, unsigned char *dns_message_buff, unsigned char *dns_buff_end, FILE *fp);

void ether_parser(char *buff, ether_head *eth, FILE *fp)
{
    fprintf(fp, "===============================================\n");
    fprintf(fp, "< Ethernet >\n");
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
        fprintf(fp, "ARP (0x%04x)", ntohs(eth->type));
    else if (ntohs(eth->type) == ETH_P_IP)
        fprintf(fp, "IPv4 (0x%04x)", ntohs(eth->type));
    else
        fprintf(fp, "Others (0x%04x)", ntohs(eth->type));
    fprintf(fp, "\n");
}

void ipv4_parser(char *buff, ip_head *ip, FILE *fp, int byte)
{
    //printf("IP detect. Captured byte: %d\n", byte);
    fprintf(fp, "-----------------------------------------------\n");
    fprintf(fp, "< Internet Protocl Version 4 protocol(IPv4) >\n");
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
    fprintf(fp, "-----------------------------------------------\n");
    fprintf(fp, "< Transmission Control Protocol(TCP) >\n");
    fprintf(fp, "Source Port: %d\n", ntohs(tcp->tcp_src));
    fprintf(fp, "Destination Port: %d\n", ntohs(tcp->tcp_dst));
    fprintf(fp, "Sequence Number: %u\n", (unsigned int)ntohl(tcp->tcp_seq));
    fprintf(fp, "Acknowledgment Number: %u\n", (unsigned int)ntohl(tcp->tcp_ackno));
    unsigned int hlen = 0;
    if ((tcp->tcp_off) & 0x08)
        hlen += 8;
    if ((tcp->tcp_off) & 0x04)
        hlen += 4;
    if ((tcp->tcp_off) & 0x02)
        hlen += 2;
    if ((tcp->tcp_off) & 0x01)
        hlen += 1;

    fprintf(fp, "TCP Header Length: %u bytes (%u)\n", hlen * 4, hlen);
    fprintf(fp, "Reserved: %c%c%c\n", ((tcp->tcp_rsv & 0x04) ? '1' : '0'), ((tcp->tcp_rsv & 0x02) ? '1' : '0'), ((tcp->tcp_rsv & 0x01) ? '1' : '0'));
    fprintf(fp, "Flags: %c%c%c%c%c%c%c%c%c\n", (tcp->tcp_ns ? 'N' : 'X'), (tcp->tcp_cwr ? 'C' : 'X'), (tcp->tcp_ece ? 'E' : 'X'), (tcp->tcp_urg ? 'U' : 'X'),
            (tcp->tcp_ack ? 'A' : 'X'), (tcp->tcp_psh ? 'P' : 'X'), (tcp->tcp_rst ? 'R' : 'X'), (tcp->tcp_syn ? 'S' : 'X'), (tcp->tcp_fin ? 'F' : 'X'));
    fprintf(fp, "Window size value: %d\n", ntohs(tcp->tcp_win_size));
    //fprintf(fp, "Calculted window size value: %d\n"); // tcp, ip option 에 대한 구현이 필요
    fprintf(fp, "Checksum: 0x%04x\n", ntohs(tcp->tcp_checksum));
    fprintf(fp, "Urgent Pointer: %d\n", ntohs(tcp->tcp_urg_ptr));
}

void udp_parser(char *buff, udp_head *udp, FILE *fp)
{
    //printf("UDP detect\n");
    fprintf(fp, "-----------------------------------------------\n");
    fprintf(fp, "< User Datagram Protocol(UDP) >\n");
    fprintf(fp, "Source Port: %d\n", ntohs(udp->udp_src));
    fprintf(fp, "Destination Port: %d\n", ntohs(udp->udp_dst));
    fprintf(fp, "Length: %d\n", ntohs(udp->udp_len));
    fprintf(fp, "Checksum: 0x%04x\n", ntohs(udp->udp_checksum));
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
    printf(" detected: ");

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
    fprintf(fp, "< Address Resolution Protocol(ARP) >\n");

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
    dump_mem(buff, ETH_HLEN + ARP_HLEN, fp);
}

void dns_parser(char *buff, dns_head *dns, FILE *fp, int dns_byte, int offset)
{
    unsigned int opcode = dns->dns_opcode;
    unsigned int rcode = dns->dns_rcode;

    fprintf(fp, "-----------------------------------------------\n");
    fprintf(fp, "< Domain Name System Protocol(DNS) >\n");
    fprintf(fp, "Transaction ID: 0x%04x\n", ntohs(dns->dns_id));
    fprintf(fp, "QR: %s (%c)\n", (dns->dns_qr ? "DNS response" : "DNS query"), (dns->dns_qr ? '1' : '0'));

    if (opcode == 0)
        fprintf(fp, "Opcode: Standard query (0)\n");
    else if (opcode == 1)
        fprintf(fp, "Opcode: Reverse query (1)\n");
    else if (opcode == 2)
        fprintf(fp, "Opcode: Server status request (2)\n");
    else
        fprintf(fp, "Opcode: ? (%d)\n", opcode);
    if (dns->dns_qr)
        fprintf(fp, "Authoritative: Server %s an authority for domain (%c)\n", (dns->dns_aa ? "is" : "is not"), (dns->dns_aa ? '1' : '0'));
    fprintf(fp, "Truncated: Message %s truncated (%c)\n", (dns->dns_tc ? "is" : "is not"), (dns->dns_tc ? '1' : '0'));
    fprintf(fp, "Recursion desired: %s query recursively (%c)\n", (dns->dns_rd ? "Do" : "Do not"), (dns->dns_rd ? '1' : '0'));

    if (dns->dns_qr)
        fprintf(fp, "Recursion available: Sever %s do recursive queries (%c)\n", (dns->dns_ra ? "can" : "can't"), (dns->dns_ra ? '1' : '0'));
    unsigned int z = dns->dns_z;
    fprintf(fp, "Z: %u\n", z);

    if (dns->dns_qr)
    {
        if (rcode == 0)
            fprintf(fp, "Reply code: No error (0)\n");
        else if (rcode == 1)
            fprintf(fp, "Reply code: Format error (1)\n");
        else if (rcode == 2)
            fprintf(fp, "Reply code: Server failure (2)\n");
        else if (rcode == 3)
            fprintf(fp, "Reply code: Name error (3)\n");
        else if (rcode == 4)
            fprintf(fp, "Reply code: Not implemented (4)\n");
        else if (rcode == 5)
            fprintf(fp, "Reply code: Refused (5)\n");
        else
            fprintf(fp, "Reply code: ? (%d)\n", rcode);
    }

    fprintf(fp, "Questions: %d\n", ntohs(dns->dns_qdc));
    int qdc = ntohs(dns->dns_qdc);
    fprintf(fp, "Answer RRs: %d\n", ntohs(dns->dns_anc));
    int anc = ntohs(dns->dns_anc);
    fprintf(fp, "Authority RRs: %d\n", ntohs(dns->dns_nsc));
    int asc = ntohs(dns->dns_nsc);
    fprintf(fp, "Additional RRs: %d\n", ntohs(dns->dns_arc));
    int arc = ntohs(dns->dns_arc);

    unsigned char *dns_buff = (unsigned char *)malloc(sizeof(char) * 1000);
    memcpy(dns_buff, buff + offset, dns_byte);
    unsigned char *dns_message_buff = dns_buff + DNS_HLEN;
    unsigned char *dns_buff_end = dns_buff + dns_byte;

    if (qdc)
    {
        fprintf(fp, "[Queries]\n");
        for (int i = 0; i < qdc; i++)
        {
            fprintf(fp, "#(%d)\n", i + 1);
            dns_message_buff = dns_query(dns_buff, dns_message_buff, dns_buff_end, fp);
        }
    }

    if (anc)
    {
        fprintf(fp, "[Answer]\n");
        for (int i = 0; i < anc; i++)
        {
            fprintf(fp, "#(%d)\n", i + 1);
            dns_message_buff = dns_answer(dns_buff, dns_message_buff, dns_buff_end, fp);
        }
    }

    if (asc)
    {
        fprintf(fp, "[Autohrity]\n");
        for (int i = 0; i < asc; i++)
        {
            fprintf(fp, "#(%d)\n", i + 1);
            dns_message_buff = dns_answer(dns_buff, dns_message_buff, dns_buff_end, fp);
        }
    }

    if (arc)
    {
        fprintf(fp, "[Additional]\n");
        for (int i = 0; i < arc; i++)
        {
            if (dns_message_buff[0] == 0x00) // OPT type
            {
                fprintf(fp, "Name: <Root>\n");
                dns_message_buff++;
                int dns_opt_type = (dns_message_buff[0] << 8) + (dns_message_buff[1]);
                if (dns_opt_type == 0x0029)
                {
                    fprintf(fp, "Type: OPT (%d)\n", dns_opt_type);
                    dns_message_buff += 2;

                    int udp_size = (dns_message_buff[0] << 8) + (dns_message_buff[1]);
                    fprintf(fp, "UDP payload size: %d\n", udp_size);
                    fprintf(fp, "Higher bits in extended RCODE: 0x%02x\n", dns_message_buff[2]);
                    fprintf(fp, "EDNS0 version: %d\n", dns_message_buff[3]);
                    dns_message_buff += 4;

                    int opt_z = (dns_message_buff[0] << 8) + (dns_message_buff[1]);
                    fprintf(fp, "Z: 0x%04x\n", opt_z);
                    dns_message_buff += 2;

                    int opt_data_len = (dns_message_buff[0] << 8) + (dns_message_buff[1]);
                    fprintf(fp, "Data length: %d\n", opt_data_len);
                    dns_message_buff += 2;
                    if (opt_data_len != 0)
                    {
                        fprintf(fp, "Data: '%.*s'\n", opt_data_len - 1, dns_message_buff + 1);
                        dns_message_buff += opt_data_len;
                    }
                }
                else
                    fprintf(fp, "Type: ? (%d)", dns_opt_type);
            }
            else
            {
                fprintf(fp, "#(%d)\n", i + 1);
                dns_message_buff = dns_answer(dns_buff, dns_message_buff, dns_buff_end, fp);
            }
        }
    }

    printf("DNS %s detected: ", (dns->dns_qr ? "response" : "query"));
    if (opcode == 0)
        printf("Standard query ");
    else if (opcode == 1)
        printf("Reverse query ");
    else if (opcode == 2)
        printf("Server status request ");
    free(dns_buff);
}

unsigned char *dns_answer(unsigned char *dns_buff, unsigned char *dns_message_buff, unsigned char *dns_buff_end, FILE *fp)
{
    dns_message_buff = dns_query(dns_buff, dns_message_buff, dns_buff_end, fp);

    unsigned int dns_ttl = (dns_message_buff[0] << 24) + (dns_message_buff[1] << 16) + (dns_message_buff[2] << 8) + (dns_message_buff[3]);
    fprintf(fp, "TTL: %u\n", dns_ttl);
    dns_message_buff += 4;
    int dns_rdl = (dns_message_buff[0] << 8) + (dns_message_buff[1]);
    fprintf(fp, "Data length: %d\n", dns_rdl);
    dns_message_buff += 2;
    char *dns_tmp = dns_message_buff - 2 - 4 - 4;
    int qtype = (dns_tmp[0] << 8) + dns_tmp[1];

    if (dns_rdl == 4 && qtype == 1)
    {
        fprintf(fp, "Rdata: Address, ");
        fprintf(fp, "%d.%d.%d.%d\n", (int)dns_message_buff[0], (int)dns_message_buff[1], (int)dns_message_buff[2], (int)dns_message_buff[3]);
    }
    else if (dns_rdl == 16 && qtype == 28)
    {
        fprintf(fp, "Rdata: IPv6, ");
        for (int i = 0; i < dns_rdl; i += 2)
        {
            fprintf(fp, "%02x%02x", dns_message_buff[i], dns_message_buff[i + 1]);
            if (i + 2 < dns_rdl)
                fprintf(fp, ":");
        }
        fprintf(fp, "\n");
    }
    else if (qtype == 5)
    {
        fprintf(fp, "Rdata: CNAME, ");
        dns_print_name(dns_buff, dns_message_buff, dns_buff_end, fp);
        fprintf(fp, "\n");
    }

    else if (dns_rdl > 3 && qtype == 15)
    {
        int p = (dns_message_buff[0] << 8) + dns_message_buff[1];
        fprintf(fp, "Rdata: MX, pref : %d, ", p);
        dns_print_name(dns_buff, dns_message_buff + 2, dns_buff_end, fp);
        fprintf(fp, "\n");
    }
    else if (qtype == 16)
        fprintf(fp, "Rdata: TXT, '%.*s'\n", dns_rdl - 1, dns_message_buff + 1);

    else
        fprintf(fp, "This type is not supported in SUPA\n");

    dns_message_buff += dns_rdl;

    return dns_message_buff;
}

unsigned char *dns_query(unsigned char *dns_buff, unsigned char *dns_message_buff, unsigned char *dns_buff_end, FILE *fp)
{
    fprintf(fp, "Name: ");
    dns_message_buff = dns_print_name(dns_buff, dns_message_buff, dns_buff_end, fp);
    fprintf(fp, "\n");

    int qtype = (dns_message_buff[0] << 8) + dns_message_buff[1];
    if (qtype == 1)
        fprintf(fp, "Type: A, Host Address (%d)\n", qtype);
    else if (qtype == 28)
        fprintf(fp, "Type: AAAA, IPv6 (%d)\n", qtype);
    else if (qtype == 5)
        fprintf(fp, "Type: CNAME, Canonical Recode Name (%d)\n", qtype);
    else if (qtype == 15)
        fprintf(fp, "Type: MX, Mail Exchange (%d)\n", qtype);
    else if (qtype == 16)
        fprintf(fp, "Type: TXT, Text Recode (%d)\n", qtype);
    else
        fprintf(fp, "Type: Others (%d)\n", qtype);
    int qclass = (dns_message_buff[2] << 8) + (dns_message_buff[3]);
    if (qclass == 0x0001)
        fprintf(fp, "Class: IN (0x%04x)\n", qclass);
    else
        fprintf(fp, "Class: NOT IN (0x%04x)\n", qclass);
    dns_message_buff = dns_message_buff + 4;

    return dns_message_buff;
}

unsigned char *dns_print_name(unsigned char *msg, unsigned char *pointer, unsigned char *end, FILE *fp)
{
    if (pointer + 2 > end)
    {
        fprintf(stderr, "<Error> : Print name 1\n");
        exit(1);
    }

    if ((*pointer & 0xc0) == 0xc0)
    {
        int k = ((*pointer & 0x3f) << 8) + pointer[1];
        pointer += 2;
        dns_print_name(msg, msg + k, end, fp);
        return pointer;
    }
    else
    {
        int length = *pointer++;
        if (pointer + length + 1 > end)
        {
            fprintf(stderr, "<Error> : Print name 2\n");
            exit(1);
        }
        fprintf(fp, "%.*s", length, pointer);
        pointer += length;
        if (*pointer != 0x00)
        {
            fprintf(fp, ".");
            return dns_print_name(msg, pointer, end, fp);
        }
        else
            return pointer + 1;
    }
}

void http_parser(char *buff, unsigned char *http_buff, int http_length, FILE *fp, int r_flag, int c_byte)
{
    fprintf(fp, "-----------------------------------------------\n");
    fprintf(fp, "< HyperText Transfer Protocol(HTTP) >\n");

    unsigned char *end_point = strstr(http_buff, "\r\n\r\n");
    int http_message_length = end_point - http_buff;

    unsigned char *http_head = (char *)malloc(sizeof(char) * http_message_length + 1);
    strncpy(http_head, http_buff, http_message_length);
    http_head[http_message_length] = '\0';

    printf("HTTP ");
    if (r_flag == HTTP_REQUEST)
        printf("Request ");
    else
        printf("Response ");
    printf("detected: ");

    int i = 0;
    char tmp;
    while (1)
    {
        tmp = http_buff[i];
        if (tmp == '\r')
            break;
        else
            printf("%c", tmp);
        i++;
    }
    printf(" ");

    if (end_point != NULL)
    {
        fprintf(fp, "%s", http_head);
        fprintf(fp, "\n");
    }

    char *data_length_field = strstr(http_head, "Content-Length: ");

    int chunk_flag = 0;
    int http_body_byte = -1;
    if (data_length_field != NULL)
    {
        data_length_field = strchr(data_length_field, ' ');
        data_length_field += 1;

        http_body_byte = strtol(data_length_field, 0, 10);
        fprintf(fp, "File data: %d bytes\n", http_body_byte);
    }
    else
    {
        char *data_chunk_field = strstr(http_head, "Transfer-Encoding: chunked");
        if (data_chunk_field != NULL)
            chunk_flag = 1;

        else
        {
            data_chunk_field = strstr(http_head, "transfer-encoding: chunked");
            if (data_chunk_field != NULL)
                chunk_flag = 1;
        }
    }

    unsigned char *http_body = end_point + 4;
    int real_body = http_length - (http_body - http_buff);

    if (chunk_flag == 1)
        fprintf(fp, "Data chunked, %d bytes in this packet\n", real_body);

    if (http_body != NULL)
    {
        if (chunk_flag == 1)
        {
            fprintf(fp, "\n");
            fprintf(fp, "<HTTP Body>\n");
            fprintf(fp, "\n");

            for (int i = 0; i < real_body; i++)
            {
                fprintf(fp, "%c", http_body[i]);
            }
            fprintf(fp, "\n");
        }
        else if (http_body_byte > 0)
        {
            fprintf(fp, "\n");
            fprintf(fp, "<HTTP Body>\n");
            fprintf(fp, "\n");

            for (int i = 0; i < real_body; i++)
            {
                fprintf(fp, "%c", http_body[i]);
            }
            fprintf(fp, "\n");
        }

        free(http_head);
    }
}

void https_parser(char *buff, FILE *fp)
{
}

void dhcp_parser(char *buff, dhcp_head *dhcp, FILE *fp, int offset)
{
    fprintf(fp, "-----------------------------------------------\n");
    fprintf(fp, "< Dynamic Host Configuration Protocol(DHCP) >\n");

    if (dhcp->dhcp_op == 1)
        fprintf(fp, "Message type: Boot Request (%d)\n", dhcp->dhcp_op);
    else if (dhcp->dhcp_op == 2)
        fprintf(fp, "Message type: Boot Response (%d)\n", dhcp->dhcp_op);

    if (dhcp->dhcp_htype == 0x01)
        fprintf(fp, "Hardware type: Ethernet (0x%02x)\n", dhcp->dhcp_htype & 0xff);
    else
        fprintf(fp, "Hardware type: ? (0x%02x)\n", dhcp->dhcp_htype & 0xff);

    fprintf(fp, "Hardware address length: %d\n", dhcp->dhcp_hlen);
    fprintf(fp, "Hops: %d\n", dhcp->dhcp_hops);
    fprintf(fp, "Transaction ID: 0x%08x\n", ntohl(dhcp->dhcp_xid));
    fprintf(fp, "Seconds elapsed: %d\n", ntohs(dhcp->dhcp_secs));
    if (ntohs(dhcp->dhcp_flags == 0))
        fprintf(fp, "Bootp flags: 0x%04x (Unicast)\n", ntohs(dhcp->dhcp_flags));
    else
        fprintf(fp, "Bootp flags: 0x%04x\n", ntohs(dhcp->dhcp_flags));
    fprintf(fp, "Client IP address: %d.%d.%d.%d\n", (dhcp->dhcp_ciaddr) & 0xff, (dhcp->dhcp_ciaddr >> 8) & 0xff, (dhcp->dhcp_ciaddr >> 16) & 0xff, (dhcp->dhcp_ciaddr >> 24) & 0xff);
    fprintf(fp, "Your (client) IP address: %d.%d.%d.%d\n", (dhcp->dhcp_yiaddr) & 0xff, (dhcp->dhcp_yiaddr >> 8) & 0xff, (dhcp->dhcp_yiaddr >> 16) & 0xff, (dhcp->dhcp_yiaddr >> 24) & 0xff);
    fprintf(fp, "Next server IP address: %d.%d.%d.%d\n", (dhcp->dhcp_siaddr) & 0xff, (dhcp->dhcp_siaddr >> 8) & 0xff, (dhcp->dhcp_siaddr >> 16) & 0xff, (dhcp->dhcp_siaddr >> 24) & 0xff);
    fprintf(fp, "Relay agent IP address: %d.%d.%d.%d\n", (dhcp->dhcp_giaddr) & 0xff, (dhcp->dhcp_giaddr >> 8) & 0xff, (dhcp->dhcp_giaddr >> 16) & 0xff, (dhcp->dhcp_giaddr >> 24) & 0xff);

    fprintf(fp, "Client MAC address: ");
    for (int i = 0; i < 6; i++)
    {
        if (i != 5)
            fprintf(fp, "%02x:", dhcp->dhcp_chaddr.chaddr[i] & 0xff);
        else
            fprintf(fp, "%02x", dhcp->dhcp_chaddr.chaddr[i] & 0xff);
    }

    fprintf(fp, "\nClient hardware address padding: ");
    for (int i = 6; i < 16; i++)
        fprintf(fp, "%02x", dhcp->dhcp_chaddr.chaddr[i] & 0xff);

    fprintf(fp, "\nServer host name: ");
    char compare[6];
    memset(compare, 0, 6);

    if (memcmp(compare, dhcp->dhcp_sname.sname, 6) == 0)
        fprintf(fp, "not given");
    else
    {
        for (int i = 0; i < 64; i++)
            fprintf(fp, "%c", (dhcp->dhcp_sname.sname[i]) & 0xff);
    }

    fprintf(fp, "\nBoot file name: ");
    if (memcmp(compare, dhcp->dhcp_file.file, 6) == 0)
        fprintf(fp, "not given");
    else
    {
        for (int i = 0; i < 64; i++)
            fprintf(fp, "%c", (dhcp->dhcp_file.file[i]) & 0xff);
    }

    unsigned char magic_cookie[4];
    magic_cookie[0] = DHCP_MAGIC_1;
    magic_cookie[1] = DHCP_MAGIC_2;
    magic_cookie[2] = DHCP_MAGIC_3;
    magic_cookie[3] = DHCP_MAGIC_4;

    unsigned char *dhcp_magic = buff + offset + DHCP_HLEN;

    if (memcmp(magic_cookie, dhcp_magic, 4) == 0)
    {
        fprintf(fp, "\nMagic cookie: DHCP\n");
        char *dhcp_option = dhcp_magic + 4;
        dhcp_option_parser(buff, dhcp, offset, fp, dhcp_option);
    }

    printf("Transaction ID: 0x%08x ", ntohl(dhcp->dhcp_xid));
}

void dhcp_option_parser(char *buff, dhcp_head *dhcp, int offset, FILE *fp, char *dhcp_option) // this function is very long
{
    // this fucntion parse the option field of DHCP packet
    unsigned char option;
    unsigned char length;
    char *dhcp_option_point = dhcp_option;
    unsigned char tmp;

    int i = 0;

    while (1)
    {
        option = (unsigned char)(*dhcp_option_point);

        if (option == DHCP_End_Of_Options)
        {
            fprintf(fp, "Options: (%d) END\n", option);
            fprintf(fp, "   Option END 255\n");
            break;
        }
        else
        {
            if (option == DHCP_Message_Type)
            {
                fprintf(fp, "Options: (%d) DHCP Message Type\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                dhcp_option_point++;
                tmp = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);

                switch (tmp)
                {
                case DHCP_Discover:
                    fprintf(fp, "   DHCP: Discover (%d)\n", tmp);
                    printf("DHCP Discover detected: ");
                    break;
                case DHCP_Offer:
                    fprintf(fp, "   DHCP: Offer (%d)\n", tmp);
                    printf("DHCP Offer detected: ");
                    break;
                case DHCP_Request:
                    fprintf(fp, "   DHCP: Request (%d)\n", tmp);
                    printf("DHCP Request detected: ");
                    break;
                case DHCP_Decline:
                    fprintf(fp, "   DHCP: Decline (%d)\n", tmp);
                    printf("DHCP Decline detected: ");
                    break;
                case DHCP_Ack:
                    fprintf(fp, "   DHCP: Ack (%d)\n", tmp);
                    printf("DHCP Ack detected: ");
                    break;
                case DHCP_NAK:
                    fprintf(fp, "   DHCP: NAK (%d)\n", tmp);
                    printf("DHCP NAK detected: ");
                    break;
                case DHCP_Release:
                    fprintf(fp, "   DHCP: Release (%d)\n", tmp);
                    printf("DHCP Release detected: ");
                    break;
                case DHCP_Inform:
                    fprintf(fp, "   DHCP: Inform (%d)\n", tmp);
                    printf("DHCP Inform detected: ");
                    break;
                case DHCP_Force_Renew:
                    fprintf(fp, "   DHCP: Force Renew (%d)\n", tmp);
                    printf("DHCP Force Renew detected: ");
                    break;
                }
            }
            else if (option == DHCP_Client_Identifier)
            {
                fprintf(fp, "Options: (%d) Client Identifier\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);

                dhcp_option_point++;
                tmp = (unsigned char)(*dhcp_option_point);
                if (tmp == 0x01)
                {
                    fprintf(fp, "   Hardware type: Ethernet (0x%02x)\n", tmp);
                    dhcp_option_point++;
                    fprintf(fp, "   Client MAC address: ");
                    for (int i = 0; i < 6; i++)
                    {
                        if (i != 5)
                            fprintf(fp, "%02x:", dhcp_option_point[i] & 0xff);

                        else
                            fprintf(fp, "%02x\n", dhcp_option_point[i] & 0xff);
                    }
                    dhcp_option_point += (length - 2);
                }

                else
                {
                    fprintf(fp, "   Hardware type: (0x%02x)\n", tmp);
                    dhcp_option_point += (length - 1);
                }
            }
            else if (option == DHCP_Requested_IP_Address)
            {
                fprintf(fp, "Options: (%d) Requested IP Address\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Requested IP Address: %d.%d.%d.%d\n", dhcp_option_point[0] & 0xff, dhcp_option_point[1] & 0xff, dhcp_option_point[2] & 0xff, dhcp_option_point[3] & 0xff);
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Hostname)
            {
                fprintf(fp, "Options: (%d) Host name\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;

                fprintf(fp, "   Host Name: ");
                for (int i = 0; i < length; i++)
                    fprintf(fp, "%c", dhcp_option_point[i]);
                fprintf(fp, "\n");

                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Client_FQDN)
            {
                fprintf(fp, "Options: (%d) Client Fully Qualified Domain Name\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Flags: 0x%02x\n", *dhcp_option_point & 0xff);
                dhcp_option_point++;
                fprintf(fp, "   A-RR result: %d\n", *dhcp_option_point & 0xff);
                dhcp_option_point++;
                fprintf(fp, "   PTR-RR result: %d\n", *dhcp_option_point & 0xff);
                dhcp_option_point++;
                fprintf(fp, "   Client Name: ");
                for (int i = 0; i < length - 3; i++)
                    fprintf(fp, "%c", dhcp_option_point[i]);
                fprintf(fp, "\n");

                dhcp_option_point += (length - 4);
            }
            else if (option == DHCP_Vendor_Class_Identifier)
            {
                fprintf(fp, "Options: (%d) Vendor class identifier\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Vendor class identifier: ");
                for (int i = 0; i < length; i++)
                    fprintf(fp, "%c", dhcp_option_point[i]);
                fprintf(fp, "\n");

                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Parameter_Request_List)
            {
                fprintf(fp, "Options: (%d) Parameter Request List\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;

                for (int i = 0; i < length; i++)
                {
                    int prl_list = dhcp_option_point[i] & 0xff;
                    fprintf(fp, "   Parameter Request List Item: (%d) ", prl_list);
                    if (prl_list < 136)
                        fprintf(fp, "%s\n", DHCP_PRL[prl_list]);
                    else if (prl_list == DHCP_Private_Classless_Static_Route_Microsoft)
                        fprintf(fp, "Private/Classless Static Route (Microsoft)\n");
                    else if (prl_list == DHCP_Private_Proxy_autodiscovery)
                        fprintf(fp, "Private/Proxy autodiscovery\n");
                    else
                        fprintf(fp, "Undefined\n");
                }

                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Pad)
            {
                fprintf(fp, "Options: (%d) Padding\n", option);
                fprintf(fp, "   Padding: %02x%02x%02x%02x\n", dhcp_option_point[0], dhcp_option_point[1], dhcp_option_point[2],dhcp_option_point[3]);
                dhcp_option_point +=3;
            }
            else if (option == DHCP_Subnet_Mask)
            {
                fprintf(fp, "Options: (%d) Subnet Mask\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Subnet Mask: %d.%d.%d.%d\n", dhcp_option_point[0] & 0xff, dhcp_option_point[1] & 0xff, dhcp_option_point[2] & 0xff, dhcp_option_point[3] & 0xff);
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Time_Offset)
            {
                fprintf(fp, "Options: (%d) Time Offset\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                int32_t *time = (int32_t *)malloc(sizeof(int32_t));
                memcpy(time, dhcp_option_point, 4);
                fprintf(fp, "   Time Offset: %d\n", (int32_t)ntohl(*time));
                free(time);
                time = NULL;
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Router_Address)
            {
                fprintf(fp, "Options: (%d) Router Address\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Router Address: ");
                for (int i = 0; i < length; i++)
                {
                    if (i % 4 == 3)
                        fprintf(fp, "%d\n", dhcp_option_point[i] & 0xff);
                    else if(i % 4 == 0)
                        fprintf(fp, "   Router: %d.", dhcp_option_point[i] & 0xff);
                    else
                        fprintf(fp, "%d.", dhcp_option_point[i] & 0xff);
                }
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Time_Server)
            {
                fprintf(fp, "Options: (%d) Time Server\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Time Server: ");
                for (int i = 0; i < length; i++)
                {
                    if (i % 4 == 3)
                        fprintf(fp, "%d\n", dhcp_option_point[i] & 0xff);
                    else if(i % 4 == 0)
                        fprintf(fp, "   Time Server: %d.", dhcp_option_point[i] & 0xff);
                    else
                        fprintf(fp, "%d.", dhcp_option_point[i] & 0xff);
                }
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_IEN_116_Name_Server)
            {
                fprintf(fp, "Options: (%d) IEN 116 Name Server\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   IEN 116 Name Server: ");
                for (int i = 0; i < length; i++)
                {
                    if (i % 4 == 3)
                        fprintf(fp, "%d\n", dhcp_option_point[i] & 0xff);
                    else if(i % 4 == 0)
                        fprintf(fp, "   Name Server: %d.", dhcp_option_point[i] & 0xff);
                    else
                        fprintf(fp, "%d.", dhcp_option_point[i] & 0xff);
                }
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Domain_Name_Server)
            {
                fprintf(fp, "Options: (%d) Domain Name Server\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                for (int i = 0; i < length; i++)
                {
                    if (i % 4 == 3)
                        fprintf(fp, "%d\n", dhcp_option_point[i] & 0xff);
                    else if(i % 4 == 0)
                        fprintf(fp, "   Domain Name Server: %d.", dhcp_option_point[i] & 0xff);
                    else
                        fprintf(fp, "%d.", dhcp_option_point[i] & 0xff);
                }
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Log_Server)
            {
                fprintf(fp, "Options: (%d) Log Sever\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Log Sever: ");
                for (int i = 0; i < length; i++)
                {
                    if (i % 4 == 3)
                        fprintf(fp, "%d\n", dhcp_option_point[i] & 0xff);
                    else if(i % 4 == 0)
                        fprintf(fp, "   Domain Name Server: %d.", dhcp_option_point[i] & 0xff);
                    else
                        fprintf(fp, "%d.", dhcp_option_point[i] & 0xff);
                }
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Cookie_Server)
            {
                fprintf(fp, "Options: (%d) Cookie Sever\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Cookie Sever: ");
                for (int i = 0; i < length; i++)
                {
                    if (i % 4 == 3)
                        fprintf(fp, "%d\n", dhcp_option_point[i] & 0xff);
                    else if(i % 4 == 0)
                        fprintf(fp, "   Cookie Server: %d.", dhcp_option_point[i] & 0xff);
                    else
                        fprintf(fp, "%d.", dhcp_option_point[i] & 0xff);
                }
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_LPR_Server)
            {
                fprintf(fp, "Options: (%d) LPR Sever\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   LPR Sever: ");
                for (int i = 0; i < length; i++)
                {
                    if (i % 4 == 3)
                        fprintf(fp, "%d\n", dhcp_option_point[i] & 0xff);
                    else if(i % 4 == 0)
                        fprintf(fp, "   LPR Server: %d.", dhcp_option_point[i] & 0xff);
                    else
                        fprintf(fp, "%d.", dhcp_option_point[i] & 0xff);
                }
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Impress_Server)
            {
                fprintf(fp, "Options: (%d) Impress Sever\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Impress Sever: ");
                for (int i = 0; i < length; i++)
                {
                    if (i % 4 == 3)
                        fprintf(fp, "%d\n", dhcp_option_point[i] & 0xff);
                    else if(i % 4 == 0)
                        fprintf(fp, "   Impress Server: %d.", dhcp_option_point[i] & 0xff);
                    else
                        fprintf(fp, "%d.", dhcp_option_point[i] & 0xff);
                }
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_RLP_Server)
            {
                fprintf(fp, "Options: (%d) Resource Location Sever\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Resource Location Sever: ");
                for (int i = 0; i < length; i++)
                {
                    if (i % 4 == 3)
                        fprintf(fp, "%d\n", dhcp_option_point[i] & 0xff);
                    else if(i % 4 == 0)
                        fprintf(fp, "   Resource Location Server: %d.", dhcp_option_point[i] & 0xff);
                    else
                        fprintf(fp, "%d.", dhcp_option_point[i] & 0xff);
                }
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Boot_File_Name)
            {
                fprintf(fp, "Options: (%d) Boot File Name\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                uint16_t *file_size = (uint16_t *)malloc(sizeof(uint16_t));
                memcpy(file_size, dhcp_option_point, 2);
                fprintf(fp, "   Boot File Name: %d\n", ntohs(*file_size));
                dhcp_option_point += (length - 1);
                free(file_size);
                file_size = NULL;
            }
            else if (option == DHCP_Merit_Dump_File)
            {
                fprintf(fp, "Options: (%d) Merit Dump File\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Merit Dump File: ");
                for (int i = 0; i < length; i++)
                    fprintf(fp, "%c", dhcp_option_point[i]);
                fprintf(fp, "\n");
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Domain_Name)
            {
                fprintf(fp, "Options: (%d) Domain Name\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Domain Name: ");

                for (int i = 0; i < length; i++)
                    fprintf(fp, "%c", dhcp_option_point[i]);
                fprintf(fp, "\n");
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Swap_Server)
            {
                fprintf(fp, "Options: (%d) Swap Server\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Swap Server: %d.%d.%d.%d\n", dhcp_option_point[0] & 0xff, dhcp_option_point[1] & 0xff, dhcp_option_point[2] & 0xff, dhcp_option_point[3] & 0xff);
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Root_Path)
            {
                fprintf(fp, "Options: (%d) Root Path\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Root Path: ");
                for (int i = 0; i < length; i++)
                    fprintf(fp, "%c", dhcp_option_point[i]);
                fprintf(fp, "\n");
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Bootp_Extensions_Path)
            {
                fprintf(fp, "Options: (%d) Extensions Path\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Extensions Path: ");
                for (int i = 0; i < length; i++)
                    fprintf(fp, "%c", dhcp_option_point[i]);
                fprintf(fp, "\n");
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_IP_Forward_Enable)
            {
                fprintf(fp, "Options: (%d) IP Forwarding Enable/Disable\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   IP Forwarding: ");
                if (dhcp_option_point[0] == 0x00)
                    fprintf(fp, "Disalbe\n");
                else
                    fprintf(fp, "Enalbe\n");
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Source_Route_Enable)
            {
                fprintf(fp, "Options: (%d) Non-Local Source Routing Enable/Disable\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Non-Local Source Routing: ");
                if (dhcp_option_point[0] == 0x00)
                    fprintf(fp, "Disalbe\n");
                else
                    fprintf(fp, "Enalbe\n");
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Policy_Filter)
            {
                fprintf(fp, "Options: (%d) Policy Filter\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Policy Filter");
                int num = length / 8;

                for (int i = 0; i < num; i++)
                {
                    fprintf(fp, "   Address (%d): ", i);
                    for (int j = i * 8; j < i * 8 + 4; j++)
                    {
                        if (j != i * 8 + 4)
                            fprintf(fp, "%d.", dhcp_option_point[j] & 0xff);
                        else
                            fprintf(fp, "%d\n", dhcp_option_point[j] & 0xff);
                    }
                    fprintf(fp, "   Mask (%d): ", i);
                    for (int j = i * 8 + 4; j < i * 8 + 8; j++)
                    {
                        if (j != i * 8 + 4)
                            fprintf(fp, "%d.", dhcp_option_point[j] & 0xff);
                        else
                            fprintf(fp, "%d\n", dhcp_option_point[j] & 0xff);
                    }
                }
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Max_Datagram_Reassembly_Sz)
            {
                fprintf(fp, "Options: (%d) Maximum Datagram Reassembly Size\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                uint16_t *size = (uint16_t*)malloc(sizeof(uint16_t));
                memcpy(size, dhcp_option_point, 2);
                fprintf(fp, "   Maximum Datagram Reassembly Size: %d\n", ntohs(*size));
                dhcp_option_point += (length - 1);
                free(size);
                size = NULL;
            }
            else if (option == DHCP_Default_IP_TTL)
            {
                fprintf(fp, "Options: (%d) IP Time-to-live\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Time-to-live: %d\n", dhcp_option_point[0]);
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Path_MTU_Aging_Timeout)
            {
                fprintf(fp, "Options: (%d) Path MTU Aging Timeout\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                uint32_t *timeout = (uint32_t *)malloc(sizeof(uint32_t));
                memcpy(timeout, dhcp_option_point, 4);
                fprintf(fp, "   Timeout: %u\n", ntohl(*timeout));
                dhcp_option_point += (length - 1);
                free(timeout);
                timeout = NULL;
            }
            else if (option == DHCP_Path_MTU_Plateau_Table)
            {
                fprintf(fp, "Options: (%d) Path MTU Plateau Table\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                int num = length / 2;
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                uint16_t *size = (uint16_t *)malloc(sizeof(uint16_t));
                for (int i = 0; i < num; i++)
                {
                    memcpy(size, dhcp_option_point + i * 2, 2);
                    fprintf(fp, "   Size (%d): %d\n", i, ntohs(*size));
                }
                dhcp_option_point += (length - 1);
                free(size);
                size = NULL;
            }
            else if (option == DHCP_Interface_MTU_Size)
            {
                fprintf(fp, "Options: (%d) Interface MTU Size\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                uint16_t *size = (uint16_t *)malloc(sizeof(uint16_t));
                memcpy(size, dhcp_option_point, 2);
                fprintf(fp, "   MTU: %d\n", ntohs(*size));
                dhcp_option_point += (length - 1);
                free(size);
                size = NULL;
            }
            else if (option == DHCP_All_Subnets_Are_Local)
            {
                fprintf(fp, "Options: (%d) All Subnets are Local\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   All Subnets are Local: ");
                if (dhcp_option_point[0] == 0x00)
                    fprintf(fp, "Some subntes may have smaller MTUs\n");
                else
                    fprintf(fp, "All subnets share the same MTU\n");
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Broadcast_Address)
            {
                fprintf(fp, "Options: (%d) Broadcast Address\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Broadcast Address: %d.%d.%d.%d\n", dhcp_option_point[0] & 0xff, dhcp_option_point[1] & 0xff, dhcp_option_point[2] & 0xff, dhcp_option_point[3] & 0xff);
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Perform_Mask_Discovery)
            {
                fprintf(fp, "Options: (%d) Perform Mask Discovery\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Perform Mask Discovery: ");
                if (dhcp_option_point[0] == 0x00)
                    fprintf(fp, "Not perform\n");
                else
                    fprintf(fp, "Perform\n");
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Provide_Mask_To_Others)
            {
                fprintf(fp, "Options: (%d) Mask Supplier\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Mask Supplier: ");
                if (dhcp_option_point[0] == 0x00)
                    fprintf(fp, "Not respond\n");
                else
                    fprintf(fp, "Respond\n");
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Perform_Router_Discovery)
            {
                fprintf(fp, "Options: (%d) Perform Router Discovery\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Perform Router Discovery: ");
                if (dhcp_option_point[0] == 0x00)
                    fprintf(fp, "Not perform\n");
                else
                    fprintf(fp, "Perform\n");
                dhcp_option_point += (length - 1);

            }
            else if (option == DHCP_Router_Solicitation_Address)
            {
                fprintf(fp, "Options: (%d) Router Solicitation Address\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Router Solicitation Address: %d.%d.%d.%d\n", dhcp_option_point[0] & 0xff, dhcp_option_point[1] & 0xff, dhcp_option_point[2] & 0xff, dhcp_option_point[3] & 0xff);
                dhcp_option_point += (length - 1);

            }
            else if (option == DHCP_Static_Routes)
            {
                fprintf(fp, "Options: (%d) Static Routes\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Static Routes");
                int num = length / 8;

                for (int i = 0; i < num; i++)
                {
                    fprintf(fp, "   Destination (%d): ", i);
                    for (int j = i * 8; j < i * 8 + 4; j++)
                    {
                        if (j != i * 8 + 4)
                            fprintf(fp, "%d.", dhcp_option_point[j] & 0xff);
                        else
                            fprintf(fp, "%d\n", dhcp_option_point[j] & 0xff);
                    }
                    fprintf(fp, "   Router (%d): ", i);
                    for (int j = i * 8 + 4; j < i * 8 + 8; j++)
                    {
                        if (j != i * 8 + 4)
                            fprintf(fp, "%d.", dhcp_option_point[j] & 0xff);
                        else
                            fprintf(fp, "%d\n", dhcp_option_point[j] & 0xff);
                    }
                }
                dhcp_option_point += (length - 1);

            }
            else if (option == DHCP_Trailer_Encapsulation)
            {
                fprintf(fp, "Options: (%d) Trailer Encapsulation\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Trailer Encapsulation: ");
                if (dhcp_option_point[0] == 0x00)
                    fprintf(fp, "Not use trailers\n");
                else
                    fprintf(fp, "Use trailers\n");
                dhcp_option_point += (length - 1);

            }
            else if (option == DHCP_ARP_Cache_Timeout)
            {
                fprintf(fp, "Options: (%d) ARP Cache Timeout\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                uint32_t *time = (uint32_t *)malloc(sizeof(uint32_t));
                memcpy(time, dhcp_option_point, 4);
                fprintf(fp, "   ARP Cache Timeout: %us\n", ntohl(*time));
                dhcp_option_point += (length - 1);
                free(time);
                time = NULL;

            }
            else if (option == DHCP_Ethernet_Encapsulation)
            {
                fprintf(fp, "Options: (%d) Ethernet Encapsulation Option\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Ethernet Encapsulation Option: ");
                if (dhcp_option_point[0] == 0x00)
                    fprintf(fp, "Use RFC 894\n");
                else
                    fprintf(fp, "Use RFC 1042\n");
                dhcp_option_point += (length - 1);

            }
            else if (option == DHCP_Default_TCP_TTL)
            {
                fprintf(fp, "Options: (%d) TCP Default TTL\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Time-to-live: %d\n", dhcp_option_point[0]);
                dhcp_option_point += (length - 1);

            }
            else if (option == DHCP_Keep_Alive_Interval)
            {
                fprintf(fp, "Options: (%d) TCP Keepalive Interval\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                uint32_t *time = (uint32_t *)malloc(sizeof(uint32_t));
                memcpy(time, dhcp_option_point, 4);
                fprintf(fp, "   TCP Keepalive Interval: %us\n", ntohl(*time));
                dhcp_option_point += (length - 1);
                free(time);
                time = NULL;
            }
            else if (option == DHCP_Keep_Alive_Garbage)
            {
                fprintf(fp, "Options: (%d) TCP Keep Alive Garbage\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   TCP Keep Alive Garbage: ");
                if (dhcp_option_point[0] == 0x00)
                    fprintf(fp, "No\n");
                else
                    fprintf(fp, "Yes\n");
                dhcp_option_point += (length - 1);

            }
            else if (option == DHCP_NIS_Domain_Name)
            {
                fprintf(fp, "Options: (%d) Network Information Service Domain\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Network Information Service Domain: ");

                for (int i = 0; i < length; i++)
                    fprintf(fp, "%c", dhcp_option_point[i]);
                fprintf(fp, "\n");
                dhcp_option_point += (length - 1);

            }

            else if (option == DHCP_Renewal_Time)
            {
                fprintf(fp, "Options: (%d) Renewal Time\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                uint32_t *time = (uint32_t *)malloc(sizeof(uint32_t));
                memcpy(time, dhcp_option_point, 4);
                fprintf(fp, "   Renewal Time: %us\n", ntohl(*time));
                dhcp_option_point += (length - 1);
                free(time);
                time = NULL;
            }
            else if (option == DHCP_Rebinding_Time)
            {
                fprintf(fp, "Options: (%d) Rebinding Time\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                uint32_t *time = (uint32_t *)malloc(sizeof(uint32_t));
                memcpy(time, dhcp_option_point, 4);
                fprintf(fp, "   Rebinding Time: %us\n", ntohl(*time));
                dhcp_option_point += (length - 1);
                free(time);
                time = NULL;
            }
            else if (option == DHCP_Error_Message)
            {
                fprintf(fp, "Options: (%d) Error Message\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;

                fprintf(fp, "   Error Message: ");
                for (int i = 0; i < length; i++)
                    fprintf(fp, "%c", dhcp_option_point[i]);
                fprintf(fp, "\n");

                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Server_Identifier)
            {
                fprintf(fp, "Options: (%d) DHCP Server Identifier\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   DHCP Server Identifier: %d.%d.%d.%d\n", dhcp_option_point[0] & 0xff, dhcp_option_point[1] & 0xff, dhcp_option_point[2] & 0xff, dhcp_option_point[3] & 0xff);
                dhcp_option_point += (length - 1);
            }
            else if (option == DHCP_Domain_Search)
            {
                fprintf(fp, "Options: (%d) Domain Search\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                fprintf(fp, "   Domain Search: ");

                for (int i = 0; i < length; i++)
                    fprintf(fp, "%c", dhcp_option_point[i]);
                fprintf(fp, "\n");
                dhcp_option_point += (length - 1);

            }
            else if (option == DHCP_IP_Address_Lease_Time)
            {
                fprintf(fp, "Options: (%d) IP Address Lease Time\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                dhcp_option_point++;
                uint32_t *timeout = (uint32_t *)malloc(sizeof(uint32_t));
                memcpy(timeout, dhcp_option_point, 4);
                fprintf(fp, "   IP Address Lease Time: %us\n", ntohl(*timeout));
                dhcp_option_point += (length - 1);
                free(timeout);
                timeout = NULL;
            }
            
            else
            {
                fprintf(fp, "Options: (%d) Not defined\n", option);
                dhcp_option_point++;
                length = (unsigned char)(*dhcp_option_point);
                fprintf(fp, "   Length: %d\n", length);
                fprintf(fp, "   Dump: 0x");
                dhcp_option_point++;
                for (int i = 0; i < length; i++)
                    fprintf(fp, "%02x ", dhcp_option_point[i] & 0xff);
                fprintf(fp, "\n");
                dhcp_option_point += (length - 1);
            }
        }

        dhcp_option_point++;
    }
}

void dump_mem(const void *mem, size_t len, FILE *fp)
{
    fprintf(fp, "\n< Memory >\n");
    fprintf(fp, "Captured byte : %ld\n", len);
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