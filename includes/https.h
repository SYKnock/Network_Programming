#include <stdint.h>

#define HTTPS_HLEN 5

typedef struct _https_head
{
    uint8_t https_content_type;
    uint16_t https_version;
    uint16_t https_length;

}https_head;