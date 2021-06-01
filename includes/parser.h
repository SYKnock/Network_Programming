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

#define HTTP_REQUEST 100
#define HTTP_RESPONSE 101

void ether_parser(char *buff, ether_head *eth, FILE *fp);
void ipv4_parser(char *buff, ip_head *ip, FILE *fp, int byte);
void tcp_parser(char *buff, tcp_head *tcp, FILE *fp);
void udp_parser(char *buff, udp_head *udp, FILE *fp);
void arp_parser(char *buff, arp_head *arp, FILE *fp);
void dns_parser(char *buff, dns_head *dns, FILE *fp, int dns_byte, int offset);
void http_parser(char *buff, unsigned char *http_buff, int http_length, FILE *fp, int r_flag);
void https_parser(char *buff, FILE *fp);
void dhcp_parser(char *buff, FILE *fp);
void dump_mem(const void *mem, size_t len, FILE *fp);

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

void http_parser(char *buff, unsigned char *http_buff, int http_length, FILE *fp, int r_flag)
{
    fprintf(fp, "-----------------------------------------------\n");
    fprintf(fp, "< HyperText Transfer Protocol(HTTP) >\n");

    unsigned char *end_point = strstr(http_buff, "\r\n\r\n");
    int http_message_length = end_point - http_buff;

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
        for (int i = 0; i < http_message_length; i++)
        {
            fprintf(fp, "%c", http_buff[i]);
        }
        fprintf(fp, "\n");
    }

    if (r_flag == HTTP_RESPONSE)
    {
        char *data_length_field = strstr(http_buff, "Content-Length: ");    
        
        if(data_length_field != NULL)
        {
            

        }

    }
}

void https_parser(char *buff, FILE *fp)
{
}

void dhcp_parser(char *buff, FILE *fp)
{
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
