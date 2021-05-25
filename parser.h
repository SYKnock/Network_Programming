#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>


#include "./includes/arp.h"
#include "./includes/dns.h"
#include "./includes/http.h"
#include "./includes/https.h"
#include "./includes/dhcp.h"
#include "./includes/ether.h"


void ether_parser(char *buff, ether_h *eth, FILE *fp);
void arp_parser(char *buff, FILE *fp);
void dns_parser(char *buff, FILE *fp);
void http_parser(char *buff, FILE *fp);
void https_parser(char *buff, FILE *fp);
void dhcp_parser(char *buff, FILE *fp);


void ether_parser(char *buff, ether_h *eth, FILE *fp)
{

    memcpy(eth, buff, ETH_HLEN);
    
}

void arp_parser(char *buff, FILE *fp)
{

    printf("ARP\n");
    
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

