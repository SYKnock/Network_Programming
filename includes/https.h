#include <stdint.h>

#define HTTPS_HLEN 5

#define SPLIT_1 1
#define SPLIT_2 2
#define SPLIT_3 3
#define SPLIT_4 4
#define SPLIT_5 5

#define CHANGE_CIPHER_SPEC 20
#define ALERT 21
#define HANDSHAKE 22
#define APPLICATION_DATA 23
#define HEARTBEAT 24
#define ACK 26

// handshake type
#define CLIENT_HELLO 1
#define SERVER_HELLO 2
#define NEW_SESSION_TICKET 4
#define END_OF_EARLY_DATA 5
#define ENCRYPTED_EXTENSIONS 8
#define CERTIFICATE 11
#define CERTIFICATE_REQUEST 13
#define CERTIFICATE_VERIFY 15
#define FINISHED 20
#define KEY_UPDATE 24
#define MESSAGE_HASH 254