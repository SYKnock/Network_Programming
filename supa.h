#include "parser.h"

void sig_handler(int signo);
void command();
void packet_sniffer();
void errProc(const char *str);

void packet_sniffer(FILE *fp)
{
    int socket_sd;
    int addr_len;
    char rbuff[BUFSIZ];
    ether_h *eth = malloc(sizeof(ether_h));
    uint16_t eth_proto;

    if ((socket_sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
        errProc("Socket error");

    while (1)
    {
        if (recv(socket_sd, rbuff, BUFSIZ - 1, 0) < 0)
            errProc("Recv error");

        ether_parser(rbuff, eth, fp);
        eth_proto = ntohs(eth->type);

        switch (eth_proto)
        {
        case ETH_P_ARP:
            arp_parser(rbuff, fp);
            break;

        case ETH_P_IP:
            printf("IP\n");
            break;

        default:
            break;
        }
    }
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

void sig_handler(int signo)
{
    printf("\n\nProgram Stop\n");
    printf("bye\n");
    exit(0);
}
