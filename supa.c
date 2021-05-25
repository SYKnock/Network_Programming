#include "supa.h"

int main()
{
    FILE *fp;
    fp = fopen("./result/log.txt", "w+");

    signal(SIGINT, (void *)sig_handler);
    printf("Limited Wireshark program\n");
    printf("This program only works in LINUX system\n");
    printf("You should set Promiscuous mod before launch the program\n");
    printf("Input \"y\" to start, \"q\" to quit\n");

    command();

    packet_sniffer(fp);
    
    fclose(fp);
    return 0;
}


