#include "supa.h"

FILE *fp;

int main(int argc, char *argv[])
{
    if(argc < 2)
    {
        printf("Usage: sudo ./supa <interface>\n");
        return 0;
    }

    
    fp = fopen("./result/log.txt", "w+");

    signal(SIGINT, (void *)sig_handler);
    printf("\n---------------SUPA---------------\n");
    printf("Limited Wireshark program\n");
    printf("This program is for LINUX system\n");
    printf("Input \"y\" to start, \"q\" to quit\n");
    printf("----------------------------------\n\n");

    command();

    packet_sniffer(fp, argv);
    
    fclose(fp);
    return 0;
}


void sig_handler(int signo)
{
    fclose(fp);
    printf("\n\nProgram Stop\n");
    printf("bye\n");
    exit(0);
}
