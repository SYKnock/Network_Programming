#include "./includes/parser.h"

void sig_handler(int signo);
void command();
void packet_sniffer(FILE *fp, char *argv[]);
void errProc(const char *str);
void ip_protocol(char *buff, ip_head *ip, FILE *fp, ether_head *eth);

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
            memcpy(ip, rbuff+ETH_HLEN, IPHRD_SIZE);
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
    fprintf(fp, "Captured byte: %d\n", captured_byte);

    //ether_parser(buff, eth, fp);
    ipv4_parser(buff, ip, fp, captured_byte);
    free(tcp);
    free(udp);
}

void tcp_protocol(char *buf, tcp_head *tcp, FILE *fp)
{

}

void udp_protocol(char *buf, udp_head *udp, FILE *fp)
{

}