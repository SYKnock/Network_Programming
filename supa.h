#include "./includes/parser.h"

int mode = 0;
int tmptmp_cnt = 0;
#define MODE_ARP 1
#define MODE_DNS 2
#define MODE_HTTP 3
#define MODE_HTTPS 4
#define MODE_DHCP 5
#define MODE_ALL 6

void sig_handler(int signo);
void command();
void select_mode();
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
    ether_head *eth = (ether_head *)malloc(sizeof(ether_head));
    arp_head *arp = (arp_head *)malloc(sizeof(arp_head));
    ip_head *ip = (ip_head *)malloc(sizeof(ip_head));

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

        if (eth_proto == ETH_P_ARP)
        {
            if (mode == MODE_ALL || mode == MODE_ARP)
            {
                fprintf(fp, "#ARP#\n");
                ether_parser(rbuff, eth, fp);
                arp_parser(rbuff, arp, fp);
            }
        }

        else if (eth_proto == ETH_P_IP)
        {
            memcpy(ip, rbuff + ETH_HLEN, IPHRD_SIZE);
            ip_protocol(rbuff, ip, fp, eth);
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
                select_mode();
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
    tcp_head *tcp = (tcp_head *)malloc(sizeof(tcp_head));
    udp_head *udp = (udp_head *)malloc(sizeof(udp_head));
    int captured_byte = ntohs(ip->ip_tot_len) + ETH_HLEN;

    if (ip->ip_protocol == IPPROTO_TCP)
        tcp_protocol(buff, tcp, fp, eth, ip, captured_byte);

    else if (ip->ip_protocol == IPPROTO_UDP)
        udp_protocol(buff, udp, fp, eth, ip, captured_byte);

    free(tcp);
    free(udp);
}

void tcp_protocol(char *buff, tcp_head *tcp, FILE *fp, ether_head *eth, ip_head *ip, int c_byte)
{
    int ip_head_length = ip->ip_hdr_len * 4;
    unsigned int tcp_head_length = tcp->tcp_off;

    memcpy(tcp, buff + ETH_HLEN + ip_head_length, TCP_HLEN);

    if ((tcp->tcp_off) & 0x08)
        tcp_head_length += 8;
    if ((tcp->tcp_off) & 0x04)
        tcp_head_length += 4;
    if ((tcp->tcp_off) & 0x02)
        tcp_head_length += 2;
    if ((tcp->tcp_off) & 0x01)
        tcp_head_length += 1;
    tcp_head_length = tcp_head_length * 4;

    if ((ntohs(tcp->tcp_src) == 53) || (ntohs(tcp->tcp_dst) == 53))
    {
        if (mode == MODE_ALL || mode == MODE_DNS)
        {
            if ((ntohl(ip->ip_src) == 0x7f000001) || (ntohl(ip->ip_dst) == 0x7f000035))
            {
            }
            else if ((ntohl(ip->ip_src) == 0x7f000035) || (ntohl(ip->ip_dst) == 0x7f000001))
            {
            }
            else
            { // check qdc count should be 0x0001
                dns_head *dns = (dns_head *)malloc(sizeof(dns_head));
                memcpy(dns, buff + ETH_HLEN + ip_head_length + tcp_head_length, DNS_HLEN);
                int qdc = ntohs(dns->dns_qdc);
                if (qdc)
                {
                    fprintf(fp, "#DNS#\n");
                    int dns_message_length = c_byte - ETH_HLEN - ip_head_length - tcp_head_length;
                    int offset = ETH_HLEN + ip_head_length + tcp_head_length;
                    ether_parser(buff, eth, fp);
                    ipv4_parser(buff, ip, fp, c_byte);
                    tcp_parser(buff, tcp, fp);
                    dns_parser(buff, dns, fp, dns_message_length, offset);
                    dump_mem(buff, c_byte, fp);
                    printf("Captured byte: %d\n", c_byte);
                }
                free(dns);
            }
        }
    }
    if ((ntohs(tcp->tcp_src) == 80) || (ntohs(tcp->tcp_dst) == 80))
    {
        if (mode == MODE_HTTP || mode == MODE_ALL)
        {
            int http_length = c_byte - ETH_HLEN - ip_head_length - tcp_head_length;
            unsigned char *http_buff = (unsigned char *)malloc(sizeof(char) * http_length);
            memcpy(http_buff, buff + ETH_HLEN + ip_head_length + tcp_head_length, http_length);

            char *check_HTTP = strstr(http_buff, "HTTP/1.1"); // check http 1.1
            if (check_HTTP != NULL)
            {
                unsigned char *check_fisrt_line = strstr(http_buff, "\r\n");
                int first_line_length = check_fisrt_line - http_buff;
                unsigned char *first_line = (char *)malloc(sizeof(char) * first_line_length + 1);
                first_line[first_line_length] = '\0';
                strncpy(first_line, http_buff, first_line_length);

                char *double_check = strstr(first_line, "HTTP/1.1"); // check http 1.1 at first line
                if (double_check != NULL)
                {
                    int r_flag;
                    if (strncmp(first_line, "HTTP", 4) != 0)
                        r_flag = HTTP_REQUEST;
                    else
                        r_flag = HTTP_RESPONSE;

                    fprintf(fp, "#HTTP#\n");
                    ether_parser(buff, eth, fp);
                    ipv4_parser(buff, ip, fp, c_byte);
                    tcp_parser(buff, tcp, fp);
                    http_parser(buff, http_buff, http_length, fp, r_flag, c_byte);
                    dump_mem(buff, c_byte, fp);
                    printf("Captured byte: %d\n", c_byte);
                }
                free(first_line);
            }
            free(http_buff);
        }
    }

    if ((ntohs(tcp->tcp_src) == 443) || (ntohs(tcp->tcp_dst) == 443)) // HTTPS
    {
        // we should merge the splitted packet
        if (mode == MODE_HTTPS || mode == MODE_ALL)
        {

            int https_length = c_byte - ETH_HLEN - ip_head_length - tcp_head_length;
            int remain = 0;
            int go_flag = 0;

            if (https_length > 0)
            {
                unsigned char *tls_section = buff + ETH_HLEN + ip_head_length + tcp_head_length;
                unsigned char c[2];
                memcpy(c, tls_section + 1, 2);
                unsigned char tmp3 = tls_section[0];
                int special_flag = 0;

                if (((c[0] == 0x03) && (c[1] == 0x03)) || ((c[0] == 0x03) && (c[1] == 0x01)) || ((c[0] == 0x03) && (c[1] == 0x02)) || ((c[0] == 0x03) && (c[1] == 0x04)) || ((c[0] == 0x03) && (c[1] == 0x00)))
                {
                    if ((tmp3 == 20) || (tmp3 == 21) || (tmp3 == 22) || (tmp3 == 23) || (tmp3 == 24) || (tmp3 == 26))
                        go_flag = 1;
                    else
                    {
                        if (split_flag == 1)
                            go_flag = 1;
                    }
                }
                else
                {
                    if (split_flag == 1)
                        go_flag = 1;
                }

                if (go_flag)
                {
                    if (split_flag == 0)
                    {
                        uint16_t size;
                        memcpy(&size, tls_section + 3, 2);
                        size = ntohs(size);

                        if (size + HTTPS_HLEN > https_length)
                        {
                            stream_size = size + HTTPS_HLEN;
                            split_flag = 1;

                            memcpy(tcp_reassem, tls_section, https_length);
                            end_tcp_stream += https_length;
                        }
                        else if (size + HTTPS_HLEN == https_length)
                        {
                            ether_parser(buff, eth, fp);
                            ipv4_parser(buff, ip, fp, c_byte);
                            tcp_parser(buff, tcp, fp);

                            remain = https_length;
                            https_parser(ip_head_length, tcp_head_length, https_length, tls_section, fp, remain, special_flag);
                            dump_mem(buff, c_byte, fp);
                            printf(" Captured byte: %d\n", c_byte);
                            
                        }
                        else if (size - HTTPS_HLEN < https_length)
                        {
                            remain = https_length;
                            ether_parser(buff, eth, fp);
                            ipv4_parser(buff, ip, fp, c_byte);
                            tcp_parser(buff, tcp, fp);
                            https_parser(ip_head_length, tcp_head_length, https_length, tls_section, fp, remain, special_flag);
                            printf(" Captured byte: %d\n", c_byte);
                            dump_mem(buff, c_byte, fp);
                            int offset = 0;
                            unsigned char *tracer = tls_section;

                            while (1)
                            {
                                uint16_t size2;
                                memcpy(&size2, tracer + 3, 2);
                                size2 = ntohs(size2);
                                if (size2 + HTTPS_HLEN > https_length - offset)
                                {
                                    stream_size = size2 + HTTPS_HLEN;
                                    split_flag = 1;

                                    memcpy(tcp_reassem, tracer, https_length - offset);
                                    end_tcp_stream += https_length - offset;
                                    break;
                                }
                                else
                                {
                                    offset += size2 + HTTPS_HLEN;
                                    tracer += size2 + HTTPS_HLEN;
                                    if (offset >= https_length)
                                        break;
                                }
                            }
                        }
                    }
                    else if (split_flag == 1)
                    {
                        unsigned char check[2];
                        memcpy(check, tls_section + 1, 2);
                        int go_flag3 = 0;

                        if (((check[0] == 0x03) && (check[1] == 0x03)) || ((check[0] == 0x03) && (check[1] == 0x01)) || ((check[0] == 0x03) && (check[1] == 0x02)) || ((check[0] == 0x03) && (check[1] == 0x04)))
                        {
                            unsigned char tmp2 = tls_section[0];
                            if((tmp2 == 20) || (tmp2 == 21) || (tmp2 == 22) || (tmp2 == 23) || (tmp2 == 24) || (tmp2 == 26))
                            {
                                uint16_t size3;
                                memcpy(&size3, tls_section + 3, 2);
                                size3 = ntohs(size3);
                                if (size3 + HTTPS_HLEN == https_length)
                                {
                                    remain = https_length;
                                    ether_parser(buff, eth, fp);
                                    ipv4_parser(buff, ip, fp, c_byte);
                                    tcp_parser(buff, tcp, fp);
                                    https_parser(ip_head_length, tcp_head_length, https_length, tls_section, fp, remain, special_flag);
                                    printf(" Captured byte: %d\n", c_byte);
                                    dump_mem(buff, c_byte, fp);
                                }
                                else if (size3 + HTTPS_HLEN < https_length)
                                {
                                    remain = https_length;
                                    ether_parser(buff, eth, fp);
                                    ipv4_parser(buff, ip, fp, c_byte);
                                    tcp_parser(buff, tcp, fp);
                                    https_parser(ip_head_length, tcp_head_length, https_length, tls_section, fp, remain, special_flag);
                                    printf(" Captured byte: %d\n", c_byte);
                                    dump_mem(buff, c_byte, fp);
                                }
                            }
                            else
                                 go_flag3 = 1;
                        }
                        else
                            go_flag3 = 1;
                        
                        if(go_flag3)
                        {
                            int flag1 = 0;
                            int tmp_offset = 0;
                            if (end_tcp_stream < stream_size)
                            {
                                if (https_length > stream_size - end_tcp_stream)
                                {
                                    memcpy(tcp_reassem + end_tcp_stream, tls_section, stream_size - end_tcp_stream);
                                    tmp_offset = stream_size - end_tcp_stream;
                                    end_tcp_stream = stream_size;
                                    remain = https_length  - (stream_size - end_tcp_stream);
                                    flag1 = 1;
                                }
                                else if (https_length < stream_size - end_tcp_stream)
                                {
                                    memcpy(tcp_reassem + end_tcp_stream, tls_section, https_length);
                                    end_tcp_stream += https_length;
                                }
                                else if (https_length == stream_size - end_tcp_stream)
                                {
                                    memcpy(tcp_reassem + end_tcp_stream, tls_section, stream_size - end_tcp_stream);
                                    tmp_offset = stream_size - end_tcp_stream;
                                    remain = 0;
                                    end_tcp_stream = stream_size;
                                }
                            }
                            if (end_tcp_stream >= stream_size)
                            {
                                special_flag = 1; 
                                ether_parser(buff, eth, fp);
                                ipv4_parser(buff, ip, fp, c_byte);
                                tcp_parser(buff, tcp, fp);
                                
                                https_parser(ip_head_length, tcp_head_length, https_length, tls_section + tmp_offset, fp, remain, special_flag);
                                printf(" Captured byte: %d\n", c_byte);
                                dump_mem(buff, c_byte, fp);

                                split_flag = 0;
                                end_tcp_stream = 0;
                                stream_size = 0;

                                if (flag1)
                                {
                                    tls_section += tmp_offset;
                                    uint16_t size4;
                                    unsigned char *tracer2 = tls_section;
                                    unsigned char check2[2];
                                    memcpy(check2, tls_section + 1, 2);
                                    if (((check2[0] == 0x03) && (check2[1] == 0x03)) || ((check2[0] == 0x03) && (check2[1] == 0x01)) || ((check2[0] == 0x03) && (check2[1] == 0x02)) || ((check[0] == 0x03) && (check2[1] == 0x04)))
                                    {
                                        while (1)
                                        {
                                            memcpy(&size4, tracer2 + 3, 2);
                                            size4 = ntohs(size4);
                                            if (size4 + HTTPS_HLEN > https_length - tmp_offset)
                                            {
                                                stream_size = size4 + HTTPS_HLEN;
                                                split_flag = 1;

                                                memcpy(tcp_reassem, tracer2, https_length - tmp_offset);
                                                end_tcp_stream += https_length - tmp_offset;
                                                break;
                                            }
                                            else
                                            {
                                                tmp_offset += size4 + HTTPS_HLEN;
                                                tracer2 += (size4 + HTTPS_HLEN);
                                                if (tmp_offset >= https_length)
                                                    break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
void udp_protocol(char *buff, udp_head *udp, FILE *fp, ether_head *eth, ip_head *ip, int c_byte)
{
    int ip_head_length = ip->ip_hdr_len * 4;

    memcpy(udp, buff + ETH_HLEN + ip_head_length, UDP_HLEN);

    if ((ntohs(udp->udp_src) == 53) || (ntohs(udp->udp_dst) == 53)) // DNS
    {
        if (mode == MODE_DNS || mode == MODE_ALL)
        {
            if ((ntohl(ip->ip_src) == 0x7f000001) || (ntohl(ip->ip_dst) == 0x7f000035)) // ignore the cached data check
            {
            }
            else if ((ntohl(ip->ip_src) == 0x7f000035) || (ntohl(ip->ip_dst) == 0x7f000001)) // ignore the cached data check
            {
            }
            else
            { // check qdc count should be 0x0001
                dns_head *dns = (dns_head *)malloc(sizeof(dns_head));
                memcpy(dns, buff + ETH_HLEN + ip_head_length + UDP_HLEN, DNS_HLEN);
                int qdc = ntohs(dns->dns_qdc);
                if (qdc)
                {
                    fprintf(fp, "#DNS#\n");
                    int dns_message_length = c_byte - ETH_HLEN - ip_head_length - UDP_HLEN;
                    int offset = ETH_HLEN + ip_head_length + UDP_HLEN;
                    ether_parser(buff, eth, fp);
                    ipv4_parser(buff, ip, fp, c_byte);
                    udp_parser(buff, udp, fp);
                    dns_parser(buff, dns, fp, dns_message_length, offset);
                    dump_mem(buff, c_byte, fp);
                    printf("Captured byte: %d\n", c_byte);
                }
                free(dns);
            }
        }
    }
    if ((ntohs(udp->udp_src) == 80) || (ntohs(udp->udp_dst) == 80)) // HTTP
    {
        if (mode == MODE_ALL || mode == MODE_HTTP)
        {
            int http_length = c_byte - ETH_HLEN - ip_head_length - UDP_HLEN;
            unsigned char *http_buff = (unsigned char *)malloc(sizeof(char) * http_length);
            memcpy(http_buff, buff + ETH_HLEN + ip_head_length + UDP_HLEN, http_length);
            char *check_HTTP = strstr(http_buff, "HTTP/1.1"); // http 1.1이 있는지 체크하고

            if (check_HTTP != NULL)
            {
                unsigned char *check_fisrt_line = strstr(http_buff, "\r\n");
                int first_line_length = check_fisrt_line - http_buff;
                unsigned char *first_line = (char *)malloc(sizeof(char) * first_line_length + 1);
                first_line[first_line_length] = '\0';
                strncpy(first_line, http_buff, first_line_length);

                char *double_check = strstr(first_line, "HTTP/1.1"); // 첫 번째 줄에 http 1.1이 있어야 http 패킷으로 인식한다
                if (double_check != NULL)
                {
                    int r_flag;
                    if (strncmp(first_line, "HTTP", 4) != 0)
                        r_flag = HTTP_REQUEST;
                    else
                        r_flag = HTTP_RESPONSE;
                    fprintf(fp, "#HTTP#\n");
                    ether_parser(buff, eth, fp);
                    ipv4_parser(buff, ip, fp, c_byte);
                    udp_parser(buff, udp, fp);
                    http_parser(buff, http_buff, http_length, fp, r_flag, c_byte);
                    dump_mem(buff, c_byte, fp);
                    printf("Captured byte: %d\n", c_byte);
                }
            }
        }
    }

    if ((ntohs(udp->udp_src) == 67) || (ntohs(udp->udp_dst) == 67) || (ntohs(udp->udp_src) == 68) || (ntohs(udp->udp_dst) == 68)) // DHCP
    {
        if (mode == MODE_ALL || mode == MODE_DHCP)
        {
            int offset = ETH_HLEN + ip_head_length + UDP_HLEN;
            unsigned char magic_cookie[4];
            magic_cookie[0] = DHCP_MAGIC_1;
            magic_cookie[1] = DHCP_MAGIC_2;
            magic_cookie[2] = DHCP_MAGIC_3;
            magic_cookie[3] = DHCP_MAGIC_4;
            unsigned char *dhcp_magic = buff + offset + DHCP_HLEN;

            if (memcmp(magic_cookie, dhcp_magic, 4) == 0) // check DHCP magic num
            {
                char *dhcp_option = dhcp_magic + 4;
                char *dhcp_option_point = dhcp_option;
                int dhcp_53_flag = 0;
                unsigned char option;
                unsigned char length;
                while (1)
                {
                    option = (unsigned char)(*dhcp_option_point);
                    if (option == DHCP_Message_Type)
                    {
                        dhcp_53_flag = 1;
                        break;
                    }
                    else if (option == DHCP_End_Of_Options)
                        break;
                    else
                    {
                        dhcp_option_point++;
                        length = (unsigned char)(*dhcp_option_point);
                        dhcp_option_point += length;
                    }
                    dhcp_option_point++;
                }
                if (dhcp_53_flag) // check whether 53 option field is exist or not
                {
                    dhcp_head *dhcp = (dhcp_head *)malloc(sizeof(dhcp_head));

                    memcpy(dhcp, buff + offset, DHCP_HLEN);
                    fprintf(fp, "#DHCP#\n");
                    ether_parser(buff, eth, fp);
                    ipv4_parser(buff, ip, fp, c_byte);
                    udp_parser(buff, udp, fp);
                    dhcp_parser(buff, dhcp, fp, offset);
                    dump_mem(buff, c_byte, fp);
                    printf("Captured byte: %d\n", c_byte);
                }
            }
        }
    }
}

void select_mode()
{
    char key[10];

    printf("Select Mode\n");
    printf("\nA for all protocols, R for ARP, D for DNS, H for HTTP, S for HTTPS, P for DHCP\n\n");

    while (1)
    {
        printf("Command>>");
        scanf("%s", key);

        if (key[0] == 'A' || key[0] == 'a')
        {
            mode = MODE_ALL;
            break;
        }

        else if (key[0] == 'R' || key[0] == 'r')
        {
            mode = MODE_ARP;
            break;
        }
        else if (key[0] == 'D' || key[0] == 'd')
        {
            mode = MODE_DNS;
            break;
        }
        else if (key[0] == 'H' || key[0] == 'h')
        {
            mode = MODE_HTTP;
            break;
        }
        else if (key[0] == 'S' || key[0] == 's')
        {
            mode = MODE_HTTPS;
            break;
        }
        else if (key[0] == 'P' || key[0] == 'p')
        {
            mode = MODE_DHCP;
            break;
        }
        else
            printf("Wrong command\n");
    }
}