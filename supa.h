#include "./includes/parser.h"

void sig_handler(int signo);
void command();
void packet_sniffer(FILE *fp, char *argv[]);
void errProc(const char *str);
void ip_protocol(char *buff, ip_head *ip, FILE *fp, ether_head *eth);
void tcp_protocol(char *buff, tcp_head *tcp, FILE *fp, ether_head *eth, ip_head *ip, int c_byte);
void udp_protocol(char *buff, udp_head *udp, FILE *fp, ether_head *eth, ip_head *ip, int c_byte);

void packet_sniffer(FILE *fp, char *argv[])
{
    int socket_sd;
    int addr_len;
    char rbuff[BUFSIZ];
    ether_head *eth = malloc(sizeof(ether_head));
    arp_head *arp = malloc(sizeof(arp_head));
    ip_head *ip = malloc(sizeof(ip_head));

    uint16_t eth_proto;
    struct ifreq ifr;

    if ((socket_sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
        errProc("Socket error");

    strncpy((char *)ifr.ifr_name, argv[1], IF_NAMESIZE);
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(socket_sd, SIOCGIFFLAGS, &ifr) == -1)
        perror("Ioctl error");

    printf("---------Program Start---------\n\n");
    while (1)
    {
        if (recv(socket_sd, rbuff, BUFSIZ - 1, 0) < 0)
            errProc("Recv error");

        memcpy(eth, rbuff, ETH_HLEN);

        eth_proto = ntohs(eth->type);

        switch (eth_proto)
        {
        case ETH_P_ARP:
            ether_parser(rbuff, eth, fp);
            arp_parser(rbuff, arp, fp);
            break;

        case ETH_P_IP:
            memcpy(ip, rbuff + ETH_HLEN, IPHRD_SIZE);
            ip_protocol(rbuff, ip, fp, eth);
            break;

        default:
            break;
        }
    }
    free(eth);
    free(ip);
    free(arp);
}

void errProc(const char *str)
{
    fprintf(stderr, "<%s: %s: >\n", str, strerror(errno));
    exit(1);
}

void command()
{
    char key[10];
    while (1)
    {
        printf("Command >> ");
        scanf("%s", key);
        if (strlen(key) != 1)
            printf("wrong command\n");
        else
        {
            if (key[0] == 'y' || key[0] == 'Y')
            {
                printf("\nUse Ctrl c to finish the program\n");
                printf("Starting...\n\n");
                break;
            }
            else if (key[0] == 'q' || key[0] == 'Q')
            {
                printf("bye\n");
                exit(0);
            }
            else
                printf("wrong command\n");
        }
    }
}

void ip_protocol(char *buff, ip_head *ip, FILE *fp, ether_head *eth)
{
    tcp_head *tcp = malloc(sizeof(tcp_head));
    udp_head *udp = malloc(sizeof(udp_head));
    int captured_byte = ntohs(ip->ip_tot_len) + ETH_HLEN;

    if (ip->ip_protocol == IPPROTO_TCP)
    {
        //tcp_protocol(buff, tcp, fp, eth, ip, captured_byte);
    }

    else if (ip->ip_protocol == IPPROTO_UDP)
        udp_protocol(buff, udp, fp, eth, ip, captured_byte);

    free(tcp);
    free(udp);
}

void tcp_protocol(char *buff, tcp_head *tcp, FILE *fp, ether_head *eth, ip_head *ip, int c_byte)
{
    // fprintf(fp, "Captured byte: %d\n", c_byte);
    int ip_head_length = ip->ip_hdr_len * 4;
    int tcp_head_length = 0;
    if ((tcp->tcp_off) & 0x08)
        tcp_head_length += 8;
    if ((tcp->tcp_off) & 0x04)
        tcp_head_length += 4;
    if ((tcp->tcp_off) & 0x02)
        tcp_head_length += 2;
    if ((tcp->tcp_off) & 0x01)
        tcp_head_length += 1;
    tcp_head_length *= 4;

    ether_parser(buff, eth, fp);
    ipv4_parser(buff, ip, fp, c_byte);
    memcpy(tcp, buff + ETH_HLEN + ip_head_length, TCP_HLEN);
    tcp_parser(buff, tcp, fp);

    if ((ntohs(tcp->tcp_src) == 53) || (ntohs(tcp->tcp_dst) == 53))
    {
    }
    else if ((ntohs(tcp->tcp_src) == 80) || (ntohs(tcp->tcp_dst) == 80))
    {
    }
    else if ((ntohs(tcp->tcp_src) == 443) || (ntohs(tcp->tcp_dst) == 443))
    {
    }
}

void udp_protocol(char *buff, udp_head *udp, FILE *fp, ether_head *eth, ip_head *ip, int c_byte)
{
    int ip_head_length = ip->ip_hdr_len * 4;

    memcpy(udp, buff + ETH_HLEN + ip_head_length, UDP_HLEN);

    if ((ntohs(udp->udp_src) == 53) || (ntohs(udp->udp_dst) == 53))
    {
        if ((ntohl(ip->ip_src) == 0x7f000001) || (ntohl(ip->ip_dst) == 0x7f000035))
        {}
        else if((ntohl(ip->ip_src) == 0x7f000035) || (ntohl(ip->ip_dst) == 0x7f000001))
        {}
        else
        {
            dns_head *dns = malloc(sizeof(dns_head));
            memcpy(dns, buff + ETH_HLEN + ip_head_length + UDP_HLEN, DNS_HLEN);
            int dns_message_length = c_byte - ETH_HLEN - ip_head_length - UDP_HLEN - DNS_HLEN;
            ether_parser(buff, eth, fp);
            ipv4_parser(buff, ip, fp, c_byte);
            udp_parser(buff, udp, fp);
            dns_parser(buff, dns, fp, dns_message_length);
            dump_mem(buff, c_byte, fp);
            printf(" Captured byte: %d\n", c_byte);
            free(dns);
        }
    }
    else if ((ntohs(udp->udp_src) == 80) || (ntohs(udp->udp_dst) == 80))
    {
    }
}