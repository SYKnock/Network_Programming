#include "./includes/parser.h"

int mode = 0;

// 모드 설정값들
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

void packet_sniffer(FILE *fp, char *argv[]) // 캡처한 패킷을 처리하는 함수
{
    int socket_sd;
    int addr_len;
    char rbuff[BUFSIZ];
    ether_head *eth = (ether_head *)malloc(sizeof(ether_head));
    arp_head *arp = (arp_head *)malloc(sizeof(arp_head));
    ip_head *ip = (ip_head *)malloc(sizeof(ip_head));

    uint16_t eth_proto;
    struct ifreq ifr;

    if ((socket_sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) // raw 소켓 생성
        errProc("Socket error");

    strncpy((char *)ifr.ifr_name, argv[1], IF_NAMESIZE);
    ifr.ifr_flags |= IFF_PROMISC; // 입력받은 NIC에 promisc 모드 설정
    if (ioctl(socket_sd, SIOCGIFFLAGS, &ifr) == -1)
        perror("Ioctl error");

    printf("---------Program Start---------\n\n");
    while (1)
    {
        if (recv(socket_sd, rbuff, BUFSIZ - 1, 0) < 0) // 패킷을 캡처함
            errProc("Recv error");

        memcpy(eth, rbuff, ETH_HLEN); // ethernet head

        eth_proto = ntohs(eth->type);

        if (eth_proto == ETH_P_ARP) // ARP 
        {
            if (mode == MODE_ALL || mode == MODE_ARP)
            {
                fprintf(fp, "#ARP#\n");
                ether_parser(rbuff, eth, fp);
                arp_parser(rbuff, arp, fp);
            }
        }

        else if (eth_proto == ETH_P_IP) // IPv4
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

void command() // command 처리 함수
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

void ip_protocol(char *buff, ip_head *ip, FILE *fp, ether_head *eth) // ip protocol 처리 함수
{
    tcp_head *tcp = (tcp_head *)malloc(sizeof(tcp_head));
    udp_head *udp = (udp_head *)malloc(sizeof(udp_head));
    int captured_byte = ntohs(ip->ip_tot_len) + ETH_HLEN;
    // ip protocol의 헤더 부분을 확인하여 해당 패킷이 TCP인지, UDP인지를 구분한다.
    if (ip->ip_protocol == IPPROTO_TCP) 
        tcp_protocol(buff, tcp, fp, eth, ip, captured_byte);

    else if (ip->ip_protocol == IPPROTO_UDP)
        udp_protocol(buff, udp, fp, eth, ip, captured_byte);

    free(tcp);
    free(udp);
}

void tcp_protocol(char *buff, tcp_head *tcp, FILE *fp, ether_head *eth, ip_head *ip, int c_byte) // tcp protocol 처리 함수
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
    tcp_head_length = tcp_head_length * 4; // tcp의 경우 헤더 길이가 옵션에 따라 가변이니 따로 계산한다.

    if ((ntohs(tcp->tcp_src) == 53) || (ntohs(tcp->tcp_dst) == 53)) // 53번 포트는 dns포트이다
    {
        if (mode == MODE_ALL || mode == MODE_DNS)
        {
            if ((ntohl(ip->ip_src) == 0x7f000001) || (ntohl(ip->ip_dst) == 0x7f000035)) // cached data check는 무시한다.
            {
            }
            else if ((ntohl(ip->ip_src) == 0x7f000035) || (ntohl(ip->ip_dst) == 0x7f000001)) // cached data check는 무시한다.
            {
            }
            else
            { // dns 패킷의 경우 QDC field의 값이 반드시 0x0001이어야 한다(이론적으로는 더 큰 값도 가능하지만, 실제로는 쓰이지 않는다). 이를 체크하고, 만족하는 경우에만 DNS로 인식하고 parsing을 진행한다.
                dns_head *dns = (dns_head *)malloc(sizeof(dns_head));
                memcpy(dns, buff + ETH_HLEN + ip_head_length + tcp_head_length, DNS_HLEN);
                int qdc = ntohs(dns->dns_qdc);
                if (qdc == 1)
                {
                    fprintf(fp, "#DNS#\n");
                    int dns_message_length = c_byte - ETH_HLEN - ip_head_length - tcp_head_length; // dns의 메시지 크기를 계산한다.
                    int offset = ETH_HLEN + ip_head_length + tcp_head_length; // 현재 버퍼 위치를 계산한다. 이런 방식을 계속해서 사용한다.
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
    if ((ntohs(tcp->tcp_src) == 80) || (ntohs(tcp->tcp_dst) == 80)) // http는 80번 포트이다.
    {
        if (mode == MODE_HTTP || mode == MODE_ALL)
        {
            int http_length = c_byte - ETH_HLEN - ip_head_length - tcp_head_length;
            unsigned char *http_buff = (unsigned char *)malloc(sizeof(char) * http_length);
            memcpy(http_buff, buff + ETH_HLEN + ip_head_length + tcp_head_length, http_length);

            char *check_HTTP = strstr(http_buff, "HTTP/1.1"); // http 1.1 문자가 있는지 체크한다. http 1.1만을 처리할 수 있다.
            if (check_HTTP != NULL)
            {
                unsigned char *check_fisrt_line = strstr(http_buff, "\r\n");
                int first_line_length = check_fisrt_line - http_buff;
                unsigned char *first_line = (char *)malloc(sizeof(char) * first_line_length + 1);
                first_line[first_line_length] = '\0';
                strncpy(first_line, http_buff, first_line_length);

                char *double_check = strstr(first_line, "HTTP/1.1"); // 문자가 있더라도, 해당 문자가 첫 번째 줄에 위치하는지 한번 더 체크한다. 
                if (double_check != NULL)
                {
                    int r_flag;
                    if (strncmp(first_line, "HTTP", 4) != 0) // 바로 HTTP가 나오는 경우에는 http request이다.
                        r_flag = HTTP_REQUEST;
                    else
                        r_flag = HTTP_RESPONSE; // 아닌 경우에는 response이다.

                    fprintf(fp, "#HTTP#\n"); // parsing을 진행한다.
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

    if ((ntohs(tcp->tcp_src) == 443) || (ntohs(tcp->tcp_dst) == 443)) // HTTPS는 443번 포트이다.
    {
        // 패킷이 여러개로 쪼개져서 도착하는 경우가 빈번하다. 따라서 이 케이스를 처리하기 위해서 stream을 사용한다.
        // stream개수는 한 개라서, 모든 패킷을 처리하지는 못한다.
        if (mode == MODE_HTTPS || mode == MODE_ALL)
        {

            int https_length = c_byte - ETH_HLEN - ip_head_length - tcp_head_length; // 현재 남아있는 버퍼의 크기를 계산한다. 그것이 https 필드의 크기가 된다.
            int remain = 0;
            int go_flag = 0; // https 패킷인지를 체크하기 위해 사용한다.

            if (https_length > 0)
            {
                unsigned char *tls_section = buff + ETH_HLEN + ip_head_length + tcp_head_length;
                unsigned char c[2];
                memcpy(c, tls_section + 1, 2);
                unsigned char tmp3 = tls_section[0];
                int special_flag = 0;

                if (((c[0] == 0x03) && (c[1] == 0x03)) || ((c[0] == 0x03) && (c[1] == 0x01)) || ((c[0] == 0x03) && (c[1] == 0x02)) || ((c[0] == 0x03) && (c[1] == 0x04)) || ((c[0] == 0x03) && (c[1] == 0x00)))
                { // 0x0303, 0x0304, 0x0302, 0x0301, 0x0300값을 반드시 가지고 있어야한다. 이것은 TLS 1.1~1.4, SSL v3을 의미한다. 이외의 프로토콜은 처리하지 않는다.
                    if ((tmp3 == 20) || (tmp3 == 21) || (tmp3 == 22) || (tmp3 == 23) || (tmp3 == 24) || (tmp3 == 26))
                        go_flag = 1; // 해당 값들은 TLS 패킷이 시작할 때 content type으로 갖는 값들이다. 이런 값이 존재하지 않는다면 TLS 패킷이 아닌 것으로 인지한다.
                    else
                    {
                        if (split_flag == 1) // 하지만 위의 조건을 충족하지 않아도, split flag가 올라가서, 현재 패킷이 쪼개져서 오는 상황이라면 어떠한 패킷이라도 받아야한다.
                            go_flag = 1;
                    }
                }
                else
                {
                    if (split_flag == 1) // 마찬가지이다.
                        go_flag = 1;
                }

                if (go_flag) // 위의 검사 조건을 만족하는 경우에만 진행한다.
                {
                    if (split_flag == 0) // 패킷이 아직 쪼개지지 않았다. 
                    {
                        uint16_t size;
                        memcpy(&size, tls_section + 3, 2);
                        size = ntohs(size);

                        if (size + HTTPS_HLEN > https_length) // 패킷의 논리 size가 물리 size보다 큰 경우는 패킷이 나눠져서 온다는 뜻이다.
                        {
                            stream_size = size + HTTPS_HLEN;
                            split_flag = 1;

                            memcpy(tcp_reassem, tls_section, https_length); // stream에 해당 내용을 저장하고 넘어간다.
                            end_tcp_stream += https_length;
                        }
                        else if (size + HTTPS_HLEN == https_length) // size가 같은 경우는 일반적으로 parsing을 진행하면 된다.
                        {
                            ether_parser(buff, eth, fp);
                            ipv4_parser(buff, ip, fp, c_byte);
                            tcp_parser(buff, tcp, fp);

                            remain = https_length;
                            https_parser(ip_head_length, tcp_head_length, https_length, tls_section, fp, remain, special_flag);
                            dump_mem(buff, c_byte, fp);
                            printf(" Captured byte: %d\n", c_byte);
                            
                        }
                        else if (size - HTTPS_HLEN < https_length) // 논리 size가 작은 경우는, 여러개의 tls 메시지가 도착했다는 뜻이다.
                        { // parsing을 진행한다.
                            remain = https_length;
                            ether_parser(buff, eth, fp);
                            ipv4_parser(buff, ip, fp, c_byte);
                            tcp_parser(buff, tcp, fp);
                            https_parser(ip_head_length, tcp_head_length, https_length, tls_section, fp, remain, special_flag);
                            printf(" Captured byte: %d\n", c_byte);
                            dump_mem(buff, c_byte, fp);
                            int offset = 0;
                            unsigned char *tracer = tls_section;

                            while (1) // 그런데, 남은 메시지들 중에서 패킷이 쪼개져야 하는 케이스도 존재한다. 이런 케이스가 있는지 확인해야한다.
                            {
                                uint16_t size2;
                                memcpy(&size2, tracer + 3, 2);
                                size2 = ntohs(size2);
                                if (size2 + HTTPS_HLEN > https_length - offset) 
                                { // 역시 고려하여 처리한다.
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
                    else if (split_flag == 1) // 패킷이 쪼개진 경우
                    {
                        unsigned char check[2];
                        memcpy(check, tls_section + 1, 2);
                        int go_flag3 = 0;

                        if (((check[0] == 0x03) && (check[1] == 0x03)) || ((check[0] == 0x03) && (check[1] == 0x01)) || ((check[0] == 0x03) && (check[1] == 0x02)) || ((check[0] == 0x03) && (check[1] == 0x04)))
                        {
                            unsigned char tmp2 = tls_section[0];
                            if((tmp2 == 20) || (tmp2 == 21) || (tmp2 == 22) || (tmp2 == 23) || (tmp2 == 24) || (tmp2 == 26))
                            { // 해당 조건을 만족하는 것은, 이 패킷은 쪼개진 것과는 관련 없다는 뜻이다. 그렇기에 독자적으로 parsing을 진행하여 처리한다.
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
                                { // 이 케이스도 위의 경우와 마찬가지이다. 가독성을 위하여 조건을 구분했다.
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
                                 go_flag3 = 1; // 시작 부분이 tls패킷이 아닌 경우는 쪼개진 패킷의 일부분들이다. stream에 합쳐야한다.
                        }
                        else
                            go_flag3 = 1;
                        
                        if(go_flag3) // stream에 합치는 작업을 진행한다.
                        {
                            int flag1 = 0;
                            int tmp_offset = 0;
                            if (end_tcp_stream < stream_size)
                            {
                                if (https_length > stream_size - end_tcp_stream) // 이 경우는 쪼개진 패킷 외에도 다른 패킷이 남아있는 경우이다.
                                {
                                    memcpy(tcp_reassem + end_tcp_stream, tls_section, stream_size - end_tcp_stream);
                                    tmp_offset = stream_size - end_tcp_stream;
                                    end_tcp_stream = stream_size;
                                    remain = https_length  - (stream_size - end_tcp_stream);
                                    flag1 = 1; // 특이 케이스이므로, 별도의 처리 과정이 필요하다
                                }
                                else if (https_length < stream_size - end_tcp_stream) // 이 경우는 아직 쪼개진게 다 오지 못한 경우이다.
                                {
                                    memcpy(tcp_reassem + end_tcp_stream, tls_section, https_length);
                                    end_tcp_stream += https_length;
                                }
                                else if (https_length == stream_size - end_tcp_stream) // 쪼개진 패킷이 다 도착한 경우이다.
                                {
                                    memcpy(tcp_reassem + end_tcp_stream, tls_section, stream_size - end_tcp_stream);
                                    tmp_offset = stream_size - end_tcp_stream;
                                    remain = 0;
                                    end_tcp_stream = stream_size;
                                }
                            }
                            if (end_tcp_stream >= stream_size) // stream에 쪼개진 패킷이 모두 도착한 경우이다.
                            { // parsing을 진행한다.
                                special_flag = 1; 
                                ether_parser(buff, eth, fp);
                                ipv4_parser(buff, ip, fp, c_byte);
                                tcp_parser(buff, tcp, fp);
                                
                                https_parser(ip_head_length, tcp_head_length, https_length, tls_section + tmp_offset, fp, remain, special_flag);
                                printf(" Captured byte: %d\n", c_byte);
                                dump_mem(buff, c_byte, fp);
                                // 스트림을 초기화한다.
                                split_flag = 0;
                                end_tcp_stream = 0;
                                stream_size = 0;

                                if (flag1) // 아까, 쪼개진걸 처리하고도 아직 내용이 남은 경우가 있었다.
                                {
                                    tls_section += tmp_offset;
                                    uint16_t size4;
                                    unsigned char *tracer2 = tls_section;
                                    unsigned char check2[2];
                                    memcpy(check2, tls_section + 1, 2);
                                    if (((check2[0] == 0x03) && (check2[1] == 0x03)) || ((check2[0] == 0x03) && (check2[1] == 0x01)) || ((check2[0] == 0x03) && (check2[1] == 0x02)) || ((check[0] == 0x03) && (check2[1] == 0x04)))
                                    { // 정상적인 tls 메시지인지 체크하고
                                        while (1)
                                        { // 패킷을 순회하며, 혹시 다시 쪼개져야 하는 것이 있는지 체크한다.
                                            memcpy(&size4, tracer2 + 3, 2);
                                            size4 = ntohs(size4);
                                            if (size4 + HTTPS_HLEN > https_length - tmp_offset)
                                            { // 발견한다면, 스트림을 다시 설정해야한다.
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
void udp_protocol(char *buff, udp_head *udp, FILE *fp, ether_head *eth, ip_head *ip, int c_byte) // udp 프로토콜을 처리한다.
{
    int ip_head_length = ip->ip_hdr_len * 4;

    memcpy(udp, buff + ETH_HLEN + ip_head_length, UDP_HLEN);

    if ((ntohs(udp->udp_src) == 53) || (ntohs(udp->udp_dst) == 53)) // DNS 프로토콜은 53번 포트를 사용한다. TCP 과정과 동일하다.
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
            { // qdc count should be 0x0001
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
    if ((ntohs(udp->udp_src) == 80) || (ntohs(udp->udp_dst) == 80)) // HTTP, TCP에서 과정과 동일하다.
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

    if ((ntohs(udp->udp_src) == 67) || (ntohs(udp->udp_dst) == 67) || (ntohs(udp->udp_src) == 68) || (ntohs(udp->udp_dst) == 68)) // DHCP. 67번 혹은 68번 포트를 사용한다.
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

            if (memcmp(magic_cookie, dhcp_magic, 4) == 0) // magic cookie값을 가지고 있는지 체크한다.
            {
                char *dhcp_option = dhcp_magic + 4;
                char *dhcp_option_point = dhcp_option;
                int dhcp_53_flag = 0; // 53번 옵션을 갖고 있는지도 체크해야한다.
                unsigned char option;
                unsigned char length;
                while (1)
                {
                    option = (unsigned char)(*dhcp_option_point);
                    if (option == DHCP_Message_Type) // 53번 옵션 여부 체크
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
                if (dhcp_53_flag) // 위의 두 조건을 모두 만족했다면, DHCP 패킷으로 인지하고 parsing을 진행한다.
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

void select_mode() // 어떤 패킷을 parsing할 지 모드를 선택하는 함수이다.
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