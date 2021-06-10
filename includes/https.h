#include <stdint.h>

#define HTTPS_HLEN 5

#define SPLIT_1 1
#define SPLIT_2 2
#define SPLIT_3 3

#define CHANGE_CIPHER_SPEC 20
#define ALERT 21
#define HANDSHAKE 22
#define APPLICATION_DATA 23
#define HEARTBEAT 24
#define ACK 26

typedef struct _https_head
{
    uint8_t https_content_type;
    uint16_t https_version;
    uint16_t https_length;

}https_head;