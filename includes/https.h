#include <stdint.h>

#define HTTPS_HLEN 5

#define SSL_HND_CERT_STATUS_TYPE_OCSP  1

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
#define SERVER_KEY_EXCHANGE 12
#define CERTIFICATE_REQUEST 13
#define SERVER_HELLO_DONE 14
#define CERTIFICATE_VERIFY 15
#define CLIENT_KEY_EXHANGE 16
#define FINISHED 20
#define KEY_UPDATE 24
#define MESSAGE_HASH 254

 #define SSL_HND_HELLO_EXT_SERVER_NAME                   0
 #define SSL_HND_HELLO_EXT_MAX_FRAGMENT_LENGTH           1
 #define SSL_HND_HELLO_EXT_CLIENT_CERTIFICATE_URL        2
 #define SSL_HND_HELLO_EXT_TRUSTED_CA_KEYS               3
 #define SSL_HND_HELLO_EXT_TRUNCATED_HMAC                4
 #define SSL_HND_HELLO_EXT_STATUS_REQUEST                5
 #define SSL_HND_HELLO_EXT_USER_MAPPING                  6
 #define SSL_HND_HELLO_EXT_CLIENT_AUTHZ                  7
 #define SSL_HND_HELLO_EXT_SERVER_AUTHZ                  8
 #define SSL_HND_HELLO_EXT_CERT_TYPE                     9
 #define SSL_HND_HELLO_EXT_SUPPORTED_GROUPS              10 /* renamed from "elliptic_curves" (RFC 7919 / TLS 1.3) */
 #define SSL_HND_HELLO_EXT_EC_POINT_FORMATS              11
 #define SSL_HND_HELLO_EXT_SRP                           12
 #define SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS          13
 #define SSL_HND_HELLO_EXT_USE_SRTP                      14
 #define SSL_HND_HELLO_EXT_HEARTBEAT                     15
 #define SSL_HND_HELLO_EXT_ALPN                          16
 #define SSL_HND_HELLO_EXT_STATUS_REQUEST_V2             17
 #define SSL_HND_HELLO_EXT_SIGNED_CERTIFICATE_TIMESTAMP  18
 #define SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE              19
 #define SSL_HND_HELLO_EXT_SERVER_CERT_TYPE              20
 #define SSL_HND_HELLO_EXT_PADDING                       21
 #define SSL_HND_HELLO_EXT_ENCRYPT_THEN_MAC              22
 #define SSL_HND_HELLO_EXT_EXTENDED_MASTER_SECRET        23
 #define SSL_HND_HELLO_EXT_TOKEN_BINDING                 24
 #define SSL_HND_HELLO_EXT_CACHED_INFO                   25
 #define SSL_HND_HELLO_EXT_COMPRESS_CERTIFICATE          27
 #define SSL_HND_HELLO_EXT_RECORD_SIZE_LIMIT             28
 /* 26-33  Unassigned*/
 #define SSL_HND_HELLO_EXT_DELEGATED_CREDENTIALS         34 /* draft-ietf-tls-subcerts-09.txt */
 #define SSL_HND_HELLO_EXT_SESSION_TICKET_TLS            35
 /* RFC 8446 (TLS 1.3) */
 #define SSL_HND_HELLO_EXT_KEY_SHARE_OLD                 40 /* draft-ietf-tls-tls13-22 (removed in -23) */
 #define SSL_HND_HELLO_EXT_PRE_SHARED_KEY                41
 #define SSL_HND_HELLO_EXT_EARLY_DATA                    42
 #define SSL_HND_HELLO_EXT_SUPPORTED_VERSIONS            43
 #define SSL_HND_HELLO_EXT_COOKIE                        44
 #define SSL_HND_HELLO_EXT_PSK_KEY_EXCHANGE_MODES        45
 #define SSL_HND_HELLO_EXT_TICKET_EARLY_DATA_INFO        46 /* draft-ietf-tls-tls13-18 (removed in -19) */
 #define SSL_HND_HELLO_EXT_CERTIFICATE_AUTHORITIES       47
 #define SSL_HND_HELLO_EXT_OID_FILTERS                   48
 #define SSL_HND_HELLO_EXT_POST_HANDSHAKE_AUTH           49
 #define SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS_CERT     50
 #define SSL_HND_HELLO_EXT_KEY_SHARE                     51
 #define SSL_HND_HELLO_EXT_CONNECTION_ID                 53
 #define SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS_V1  57 /* draft-ietf-quic-tls-33 */
 #define SSL_HND_HELLO_EXT_GREASE_0A0A                   2570
 #define SSL_HND_HELLO_EXT_GREASE_1A1A                   6682
 #define SSL_HND_HELLO_EXT_GREASE_2A2A                   10794
 #define SSL_HND_HELLO_EXT_NPN                           13172 /* 0x3374 */
 #define SSL_HND_HELLO_EXT_GREASE_3A3A                   14906
 #define SSL_HND_HELLO_EXT_ALPS                          17513 /* draft-vvv-tls-alps-01, temporary value used in BoringSSL implementation */
 #define SSL_HND_HELLO_EXT_GREASE_4A4A                   19018
 #define SSL_HND_HELLO_EXT_GREASE_5A5A                   23130
 #define SSL_HND_HELLO_EXT_GREASE_6A6A                   27242
 #define SSL_HND_HELLO_EXT_CHANNEL_ID_OLD                30031 /* 0x754f */
 #define SSL_HND_HELLO_EXT_CHANNEL_ID                    30032 /* 0x7550 */
 #define SSL_HND_HELLO_EXT_GREASE_7A7A                   31354
 #define SSL_HND_HELLO_EXT_GREASE_8A8A                   35466
 #define SSL_HND_HELLO_EXT_GREASE_9A9A                   39578
 #define SSL_HND_HELLO_EXT_GREASE_AAAA                   43690
 #define SSL_HND_HELLO_EXT_GREASE_BABA                   47802
 #define SSL_HND_HELLO_EXT_GREASE_CACA                   51914
 #define SSL_HND_HELLO_EXT_GREASE_DADA                   56026
 #define SSL_HND_HELLO_EXT_GREASE_EAEA                   60138
 #define SSL_HND_HELLO_EXT_GREASE_FAFA                   64250
 #define SSL_HND_HELLO_EXT_RENEGOTIATION_INFO            65281 /* 0xFF01 */
 #define SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS     65445 /* 0xffa5 draft-ietf-quic-tls-13 */
 #define SSL_HND_HELLO_EXT_ENCRYPTED_SERVER_NAME         65486 /* 0xffce draft-ietf-tls-esni-01 */


typedef struct _value_name
{
    unsigned int value;
    char *name;
} value_name;

static const value_name ssl_31_ciphersuite[] = {
    /* RFC 2246, RFC 4346, RFC 5246 */
    {0x0000, "TLS_NULL_WITH_NULL_NULL"},
    {0x0001, "TLS_RSA_WITH_NULL_MD5"},
    {0x0002, "TLS_RSA_WITH_NULL_SHA"},
    {0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"},
    {0x0004, "TLS_RSA_WITH_RC4_128_MD5"},
    {0x0005, "TLS_RSA_WITH_RC4_128_SHA"},
    {0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"},
    {0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA"},
    {0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"},
    {0x0009, "TLS_RSA_WITH_DES_CBC_SHA"},
    {0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0x000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"},
    {0x000c, "TLS_DH_DSS_WITH_DES_CBC_SHA"},
    {0x000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"},
    {0x000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"},
    {0x000f, "TLS_DH_RSA_WITH_DES_CBC_SHA"},
    {0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"},
    {0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA"},
    {0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"},
    {0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"},
    {0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA"},
    {0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"},
    {0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"},
    {0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"},
    {0x001a, "TLS_DH_anon_WITH_DES_CBC_SHA"},
    {0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"},

    {0x001c, "SSL_FORTEZZA_KEA_WITH_NULL_SHA"},
    {0x001d, "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"},
#if 0 /* Because it clashes with KRB5, is never used any more, and is safe \
         to remove according to David Hopwood <david.hopwood@zetnet.co.uk> \
         of the ietf-tls list */
    { 0x001e, "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA" },
#endif
    /* RFC 2712 */
    {0x001E, "TLS_KRB5_WITH_DES_CBC_SHA"},
    {0x001F, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"},
    {0x0020, "TLS_KRB5_WITH_RC4_128_SHA"},
    {0x0021, "TLS_KRB5_WITH_IDEA_CBC_SHA"},
    {0x0022, "TLS_KRB5_WITH_DES_CBC_MD5"},
    {0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"},
    {0x0024, "TLS_KRB5_WITH_RC4_128_MD5"},
    {0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5"},
    {0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"},
    {0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"},
    {0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"},
    {0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"},
    {0x002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"},
    {0x002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"},
    /* RFC 4785 */
    {0x002C, "TLS_PSK_WITH_NULL_SHA"},
    {0x002D, "TLS_DHE_PSK_WITH_NULL_SHA"},
    {0x002E, "TLS_RSA_PSK_WITH_NULL_SHA"},
    /* RFC 5246 */
    {0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"},
    {0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA"},
    {0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA"},
    {0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"},
    {0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"},
    {0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA"},
    {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"},
    {0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA"},
    {0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA"},
    {0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"},
    {0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"},
    {0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA"},
    {0x003B, "TLS_RSA_WITH_NULL_SHA256"},
    {0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256"},
    {0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256"},
    {0x003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"},
    {0x003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"},
    {0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"},
    /* RFC 4132 */
    {0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"},
    /* 0x00,0x60-66 Reserved to avoid conflicts with widely deployed implementations  */
    /* --- ??? --- */
    {0x0060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5"},
    {0x0061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"},
    /* draft-ietf-tls-56-bit-ciphersuites-01.txt */
    {0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"},
    {0x0063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"},
    {0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"},
    {0x0065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"},
    {0x0066, "TLS_DHE_DSS_WITH_RC4_128_SHA"},
    /* --- ??? ---*/
    {0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"},
    {0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"},
    {0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"},
    {0x006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"},
    {0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"},
    {0x006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256"},
    {0x006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256"},
    /* draft-chudov-cryptopro-cptls-04.txt */
    {0x0080, "TLS_GOSTR341094_WITH_28147_CNT_IMIT"},
    {0x0081, "TLS_GOSTR341001_WITH_28147_CNT_IMIT"},
    {0x0082, "TLS_GOSTR341094_WITH_NULL_GOSTR3411"},
    {0x0083, "TLS_GOSTR341001_WITH_NULL_GOSTR3411"},
    /* RFC 4132 */
    {0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"},
    {0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"},
    {0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"},
    {0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"},
    {0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"},
    {0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"},
    /* RFC 4279 */
    {0x008A, "TLS_PSK_WITH_RC4_128_SHA"},
    {0x008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA"},
    {0x008C, "TLS_PSK_WITH_AES_128_CBC_SHA"},
    {0x008D, "TLS_PSK_WITH_AES_256_CBC_SHA"},
    {0x008E, "TLS_DHE_PSK_WITH_RC4_128_SHA"},
    {0x008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"},
    {0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"},
    {0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"},
    {0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA"},
    {0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"},
    {0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"},
    {0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"},
    /* RFC 4162 */
    {0x0096, "TLS_RSA_WITH_SEED_CBC_SHA"},
    {0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA"},
    {0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA"},
    {0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA"},
    {0x009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA"},
    {0x009B, "TLS_DH_anon_WITH_SEED_CBC_SHA"},
    /* RFC 5288 */
    {0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
    {0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
    {0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},
    {0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"},
    {0x00A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"},
    {0x00A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"},
    {0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"},
    {0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"},
    {0x00A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"},
    {0x00A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"},
    {0x00A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256"},
    {0x00A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384"},
    /* RFC 5487 */
    {0x00A8, "TLS_PSK_WITH_AES_128_GCM_SHA256"},
    {0x00A9, "TLS_PSK_WITH_AES_256_GCM_SHA384"},
    {0x00AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"},
    {0x00AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"},
    {0x00AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"},
    {0x00AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"},
    {0x00AE, "TLS_PSK_WITH_AES_128_CBC_SHA256"},
    {0x00AF, "TLS_PSK_WITH_AES_256_CBC_SHA384"},
    {0x00B0, "TLS_PSK_WITH_NULL_SHA256"},
    {0x00B1, "TLS_PSK_WITH_NULL_SHA384"},
    {0x00B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"},
    {0x00B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"},
    {0x00B4, "TLS_DHE_PSK_WITH_NULL_SHA256"},
    {0x00B5, "TLS_DHE_PSK_WITH_NULL_SHA384"},
    {0x00B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"},
    {0x00B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"},
    {0x00B8, "TLS_RSA_PSK_WITH_NULL_SHA256"},
    {0x00B9, "TLS_RSA_PSK_WITH_NULL_SHA384"},
    /* From RFC 5932 */
    {0x00BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00BB, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00BC, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00BD, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00C1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00C2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00C3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"},
    /* RFC 8998 */
    {0x00C6, "TLS_SM4_GCM_SM3"},
    {0x00C7, "TLS_SM4_CCM_SM3"},
    /* 0x00,0xC8-FE Unassigned */
    /* From RFC 5746 */
    {0x00FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"},
    /* RFC 8701 */
    {0x0A0A, "Reserved (GREASE)"},
    /* RFC 8446 */
    {0x1301, "TLS_AES_128_GCM_SHA256"},
    {0x1302, "TLS_AES_256_GCM_SHA384"},
    {0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
    {0x1304, "TLS_AES_128_CCM_SHA256"},
    {0x1305, "TLS_AES_128_CCM_8_SHA256"},
    /* RFC 8701 */
    {0x1A1A, "Reserved (GREASE)"},
    {0x2A2A, "Reserved (GREASE)"},
    {0x3A3A, "Reserved (GREASE)"},
    {0x4A4A, "Reserved (GREASE)"},
    /* From RFC 7507 */
    {0x5600, "TLS_FALLBACK_SCSV"},
    /* RFC 8701 */
    {0x5A5A, "Reserved (GREASE)"},
    {0x6A6A, "Reserved (GREASE)"},
    {0x7A7A, "Reserved (GREASE)"},
    {0x8A8A, "Reserved (GREASE)"},
    {0x9A9A, "Reserved (GREASE)"},
    {0xAAAA, "Reserved (GREASE)"},
    {0xBABA, "Reserved (GREASE)"},
    /* From RFC 4492 */
    {0xc001, "TLS_ECDH_ECDSA_WITH_NULL_SHA"},
    {0xc002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"},
    {0xc003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"},
    {0xc004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"},
    {0xc005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"},
    {0xc006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"},
    {0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"},
    {0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"},
    {0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
    {0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"},
    {0xc00b, "TLS_ECDH_RSA_WITH_NULL_SHA"},
    {0xc00c, "TLS_ECDH_RSA_WITH_RC4_128_SHA"},
    {0xc00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0xc00e, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"},
    {0xc00f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"},
    {0xc010, "TLS_ECDHE_RSA_WITH_NULL_SHA"},
    {0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
    {0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
    {0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
    {0xc015, "TLS_ECDH_anon_WITH_NULL_SHA"},
    {0xc016, "TLS_ECDH_anon_WITH_RC4_128_SHA"},
    {0xc017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"},
    {0xc018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"},
    {0xc019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"},
    /* RFC 5054 */
    {0xC01A, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"},
    {0xC01B, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0xC01C, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"},
    {0xC01D, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"},
    {0xC01E, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"},
    {0xC01F, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"},
    {0xC020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"},
    {0xC021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"},
    {0xC022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"},
    /* RFC 5589 */
    {0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"},
    {0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
    {0xC025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"},
    {0xC026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"},
    {0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},
    {0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"},
    {0xC029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"},
    {0xC02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"},
    {0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
    {0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
    {0xC02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"},
    {0xC02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"},
    {0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
    {0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
    {0xC031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"},
    {0xC032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"},
    /* RFC 5489 */
    {0xC033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA"},
    {0xC034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"},
    {0xC035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"},
    {0xC036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"},
    {0xC037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"},
    {0xC038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"},
    {0xC039, "TLS_ECDHE_PSK_WITH_NULL_SHA"},
    {0xC03A, "TLS_ECDHE_PSK_WITH_NULL_SHA256"},
    {0xC03B, "TLS_ECDHE_PSK_WITH_NULL_SHA384"},
    /* RFC 6209 */
    {0xC03C, "TLS_RSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC03D, "TLS_RSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC03E, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"},
    {0xC03F, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"},
    {0xC040, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC041, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC042, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"},
    {0xC043, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"},
    {0xC044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"},
    {0xC047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"},
    {0xC048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC04A, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC04B, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC04C, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC04D, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC04E, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC04F, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC054, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC055, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"},
    {0xC057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"},
    {0xC058, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"},
    {0xC059, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"},
    {0xC05A, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"},
    {0xC05B, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"},
    {0xC05C, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC05D, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC05E, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC05F, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC064, "TLS_PSK_WITH_ARIA_128_CBC_SHA256"},
    {0xC065, "TLS_PSK_WITH_ARIA_256_CBC_SHA384"},
    {0xC066, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"},
    {0xC067, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"},
    {0xC068, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"},
    {0xC069, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"},
    {0xC06A, "TLS_PSK_WITH_ARIA_128_GCM_SHA256"},
    {0xC06B, "TLS_PSK_WITH_ARIA_256_GCM_SHA384"},
    {0xC06C, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"},
    {0xC06D, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"},
    {0xC06E, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"},
    {0xC06F, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"},
    {0xC070, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"},
    {0xC071, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"},
    /* RFC 6367 */
    {0xC072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC074, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC075, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC078, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC079, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC07A, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC07B, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC07C, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC07D, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC07E, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC07F, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC080, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC081, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC082, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC083, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC084, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC085, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC088, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC089, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC08A, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC08B, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC08C, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC08D, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC08E, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC08F, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC090, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC091, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC092, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC093, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC094, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC095, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC096, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC097, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC098, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC099, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC09A, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC09B, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"},
    /* RFC 6655 */
    {0xC09C, "TLS_RSA_WITH_AES_128_CCM"},
    {0xC09D, "TLS_RSA_WITH_AES_256_CCM"},
    {0xC09E, "TLS_DHE_RSA_WITH_AES_128_CCM"},
    {0xC09F, "TLS_DHE_RSA_WITH_AES_256_CCM"},
    {0xC0A0, "TLS_RSA_WITH_AES_128_CCM_8"},
    {0xC0A1, "TLS_RSA_WITH_AES_256_CCM_8"},
    {0xC0A2, "TLS_DHE_RSA_WITH_AES_128_CCM_8"},
    {0xC0A3, "TLS_DHE_RSA_WITH_AES_256_CCM_8"},
    {0xC0A4, "TLS_PSK_WITH_AES_128_CCM"},
    {0xC0A5, "TLS_PSK_WITH_AES_256_CCM"},
    {0xC0A6, "TLS_DHE_PSK_WITH_AES_128_CCM"},
    {0xC0A7, "TLS_DHE_PSK_WITH_AES_256_CCM"},
    {0xC0A8, "TLS_PSK_WITH_AES_128_CCM_8"},
    {0xC0A9, "TLS_PSK_WITH_AES_256_CCM_8"},
    {0xC0AA, "TLS_PSK_DHE_WITH_AES_128_CCM_8"},
    {0xC0AB, "TLS_PSK_DHE_WITH_AES_256_CCM_8"},
    /* RFC 7251 */
    {0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"},
    {0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"},
    {0xC0AE, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"},
    {0xC0AF, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"},
    /* RFC 8492 */
    {0xC0B0, "TLS_ECCPWD_WITH_AES_128_GCM_SHA256"},
    {0xC0B1, "TLS_ECCPWD_WITH_AES_256_GCM_SHA384"},
    {0xC0B2, "TLS_ECCPWD_WITH_AES_128_CCM_SHA256"},
    {0xC0B3, "TLS_ECCPWD_WITH_AES_256_CCM_SHA384"},
    /* draft-camwinget-tls-ts13-macciphersuites */
    {0xC0B4, "TLS_SHA256_SHA256"},
    {0xC0B5, "TLS_SHA384_SHA384"},
    /* https://www.ietf.org/archive/id/draft-cragie-tls-ecjpake-01.txt */
    {0xC0FF, "TLS_ECJPAKE_WITH_AES_128_CCM_8"},
    /* draft-smyshlyaev-tls12-gost-suites */
    {0xC100, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC"},
    {0xC101, "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC"},
    {0xC102, "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"},
    /* draft-smyshlyaev-tls13-gost-suites */
    {0xC103, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L"},
    {0xC104, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L"},
    {0xC105, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S"},
    {0xC106, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S"},
    /* RFC 8701 */
    {0xCACA, "Reserved (GREASE)"},
    /*
0xC0,0xAB-FF Unassigned
0xC1,0x03-FD,* Unassigned
0xFE,0x00-FD Unassigned
0xFE,0xFE-FF Reserved to avoid conflicts with widely deployed implementations [Pasi_Eronen]
0xFF,0x00-FF Reserved for Private Use [RFC5246]
*/
    /* old numbers used in the beginning
     * https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305 */
    {0xCC13, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCC14, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCC15, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
    /* RFC 7905 */
    {0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAB, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAC, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAD, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAE, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"},
    /* https://tools.ietf.org/html/draft-ietf-tls-ecdhe-psk-aead */
    {0xD001, "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"},
    {0xD002, "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"},
    {0xD003, "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256"},
    {0xD005, "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256"},
    /* RFC 8701 */
    {0xDADA, "Reserved (GREASE)"},
    /* GM/T 0024-2014 */
    {0xe001, "ECDHE_SM1_SM3"},
    {0xe003, "ECC_SM1_SM3"},
    {0xe005, "IBSDH_SM1_SM3"},
    {0xe007, "IBC_SM1_SM3"},
    {0xe009, "RSA_SM1_SM3"},
    {0xe00a, "RSA_SM1_SHA1"},
    {0xe011, "ECDHE_SM4_SM3"},
    {0xe013, "ECC_SM4_SM3"},
    {0xe015, "IBSDH_SM4_SM3"},
    {0xe017, "IBC_SM4_SM3"},
    {0xe019, "RSA_SM4_SM3"},
    {0xe01a, "RSA_SM4_SHA1"},
    /* https://tools.ietf.org/html/draft-josefsson-salsa20-tls */
    {0xE410, "TLS_RSA_WITH_ESTREAM_SALSA20_SHA1"},
    {0xE411, "TLS_RSA_WITH_SALSA20_SHA1"},
    {0xE412, "TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1"},
    {0xE413, "TLS_ECDHE_RSA_WITH_SALSA20_SHA1"},
    {0xE414, "TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1"},
    {0xE415, "TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1"},
    {0xE416, "TLS_PSK_WITH_ESTREAM_SALSA20_SHA1"},
    {0xE417, "TLS_PSK_WITH_SALSA20_SHA1"},
    {0xE418, "TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1"},
    {0xE419, "TLS_ECDHE_PSK_WITH_SALSA20_SHA1"},
    {0xE41A, "TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1"},
    {0xE41B, "TLS_RSA_PSK_WITH_SALSA20_SHA1"},
    {0xE41C, "TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1"},
    {0xE41D, "TLS_DHE_PSK_WITH_SALSA20_SHA1"},
    {0xE41E, "TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1"},
    {0xE41F, "TLS_DHE_RSA_WITH_SALSA20_SHA1"},
    /* RFC 8701 */
    {0xEAEA, "Reserved (GREASE)"},
    {0xFAFA, "Reserved (GREASE)"},
    /* these from http://www.mozilla.org/projects/
         security/pki/nss/ssl/fips-ssl-ciphersuites.html */
    {0xfefe, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    {0xfeff, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"},
    {0xffe0, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"},
    {0xffe1, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    /* note that ciphersuites 0xff00 - 0xffff are private */
    {0x00, NULL}};

const value_name tls_hello_ext_server_name_type_vs[] = {
    {0, "host_name"},
    {0, NULL}};

/* RFC 6066 Section 4 */
const value_name tls_hello_ext_max_fragment_length[] = {
    {1, "512"},  // 2^9
    {2, "1024"}, // 2^10
    {3, "2048"}, // 2^11
    {4, "4096"}, // 2^12
    {0, NULL}};

/* RFC 8446 Section 4.2.9 */
const value_name tls_hello_ext_psk_ke_mode[] = {
    {0, "PSK-only key establishment (psk_ke)"},
    {1, "PSK with (EC)DHE key establishment (psk_dhe_ke)"},
    {0, NULL}};


const value_name tls_hello_ext_supported_version[] = {
    {0x0300, "SSLv3"},
    {0x0301, "TLS 1.0"},
    {0x0302, "TLS 1.1"},
    {0x0303, "TLS 1.2"},
    {0x0304, "TLS 1.3"}
};

const value_name tls13_key_update_request[] = {
    {0, "update_not_requested"},
    {1, "update_requested"},
    {0, NULL}};

/* RFC 5246 7.4.1.4.1 */
const value_name tls_hash_algorithm[] = {
    {0, "None"},
    {1, "MD5"},
    {2, "SHA1"},
    {3, "SHA224"},
    {4, "SHA256"},
    {5, "SHA384"},
    {6, "SHA512"},
    {7, "SM3"},
    {0, NULL}};

const value_name tls_signature_algorithm[] = {
    {0, "Anonymous"},
    {1, "RSA"},
    {2, "DSA"},
    {3, "ECDSA"},
    {4, "SM2"},
    {0, NULL}};

/* RFC 8446 Section 4.2.3 */
const value_name tls13_signature_algorithm[] = {
    {0x0201, "rsa_pkcs1_sha1"},
    {0x0203, "ecdsa_sha1"},
    {0x0401, "rsa_pkcs1_sha256"},
    {0x0403, "ecdsa_secp256r1_sha256"},
    {0x0501, "rsa_pkcs1_sha384"},
    {0x0503, "ecdsa_secp384r1_sha384"},
    {0x0601, "rsa_pkcs1_sha512"},
    {0x0603, "ecdsa_secp521r1_sha512"},
    {0x0708, "sm2sig_sm3"},
    {0x0804, "rsa_pss_rsae_sha256"},
    {0x0805, "rsa_pss_rsae_sha384"},
    {0x0806, "rsa_pss_rsae_sha512"},
    {0x0807, "ed25519"},
    {0x0808, "ed448"},
    {0x0809, "rsa_pss_pss_sha256"},
    {0x080a, "rsa_pss_pss_sha384"},
    {0x080b, "rsa_pss_pss_sha512"},
    {0, NULL}};

const value_name ssl_31_compression_method[] = {
    {0, "null"},
    {1, "DEFLATE"},
    {64, "LZS"},
    {0x00, NULL}};

const value_name ssl_extension_curves[] = {
    {  1, "sect163k1" },
    {  2, "sect163r1" },
    {  3, "sect163r2" },
    {  4, "sect193r1" },
    {  5, "sect193r2" },
    {  6, "sect233k1" },
    {  7, "sect233r1" },
    {  8, "sect239k1" },
    {  9, "sect283k1" },
    { 10, "sect283r1" },
    { 11, "sect409k1" },
    { 12, "sect409r1" },
    { 13, "sect571k1" },
    { 14, "sect571r1" },
    { 15, "secp160k1" },
    { 16, "secp160r1" },
    { 17, "secp160r2" },
    { 18, "secp192k1" },
    { 19, "secp192r1" },
    { 20, "secp224k1" },
    { 21, "secp224r1" },
    { 22, "secp256k1" },
    { 23, "secp256r1" },
    { 24, "secp384r1" },
    { 25, "secp521r1" },
    { 26, "brainpoolP256r1" }, /* RFC 7027 */
    { 27, "brainpoolP384r1" }, /* RFC 7027 */
    { 28, "brainpoolP512r1" }, /* RFC 7027 */
    { 29, "x25519" }, /* RFC 8446 / RFC 8422 */
    { 30, "x448" }, /* RFC 8446 / RFC 8422 */
    { 41, "curveSM2" }, /* RFC 8998 */
    { 256, "ffdhe2048" }, /* RFC 7919 */
    { 257, "ffdhe3072" }, /* RFC 7919 */
    { 258, "ffdhe4096" }, /* RFC 7919 */
    { 259, "ffdhe6144" }, /* RFC 7919 */
    { 260, "ffdhe8192" }, /* RFC 7919 */
    { 2570, "Reserved (GREASE)" }, /* RFC 8701 */
    { 6682, "Reserved (GREASE)" }, /* RFC 8701 */
    { 10794, "Reserved (GREASE)" }, /* RFC 8701 */
    { 14906, "Reserved (GREASE)" }, /* RFC 8701 */
    { 19018, "Reserved (GREASE)" }, /* RFC 8701 */
    { 23130, "Reserved (GREASE)" }, /* RFC 8701 */
    { 27242, "Reserved (GREASE)" }, /* RFC 8701 */
    { 31354, "Reserved (GREASE)" }, /* RFC 8701 */
    { 35466, "Reserved (GREASE)" }, /* RFC 8701 */
    { 39578, "Reserved (GREASE)" }, /* RFC 8701 */
    { 43690, "Reserved (GREASE)" }, /* RFC 8701 */
    { 47802, "Reserved (GREASE)" }, /* RFC 8701 */
    { 51914, "Reserved (GREASE)" }, /* RFC 8701 */
    { 56026, "Reserved (GREASE)" }, /* RFC 8701 */
    { 60138, "Reserved (GREASE)" }, /* RFC 8701 */
    { 64250, "Reserved (GREASE)" }, /* RFC 8701 */
    { 0xFF01, "arbitrary_explicit_prime_curves" },
    { 0xFF02, "arbitrary_explicit_char2_curves" },
    { 0x00, NULL }
};

const value_name ssl_curve_types[] = {
    { 1, "explicit_prime" },
    { 2, "explicit_char2" },
    { 3, "named_curve" },
    { 0x00, NULL }
};

const value_name ssl_extension_ec_point_formats[] = {
    { 0, "uncompressed" },
    { 1, "ansiX962_compressed_prime" },
    { 2, "ansiX962_compressed_char2" },
    { 0x00, NULL }
};

const value_name ssl_20_certificate_type[] = {
    { 0x00, "N/A" },
    { 0x01, "X.509 Certificate" },
    { 0x00, NULL }
};


const value_name tls_hello_extension_types[] = {
    { SSL_HND_HELLO_EXT_SERVER_NAME, "server_name" }, /* RFC 6066 */
    { SSL_HND_HELLO_EXT_MAX_FRAGMENT_LENGTH, "max_fragment_length" },/* RFC 6066 */
    { SSL_HND_HELLO_EXT_CLIENT_CERTIFICATE_URL, "client_certificate_url" }, /* RFC 6066 */
    { SSL_HND_HELLO_EXT_TRUSTED_CA_KEYS, "trusted_ca_keys" }, /* RFC 6066 */
    { SSL_HND_HELLO_EXT_TRUNCATED_HMAC, "truncated_hmac" }, /* RFC 6066 */
    { SSL_HND_HELLO_EXT_STATUS_REQUEST, "status_request" }, /* RFC 6066 */
    { SSL_HND_HELLO_EXT_USER_MAPPING, "user_mapping" }, /* RFC 4681 */
    { SSL_HND_HELLO_EXT_CLIENT_AUTHZ, "client_authz" }, /* RFC 5878 */
    { SSL_HND_HELLO_EXT_SERVER_AUTHZ, "server_authz" }, /* RFC 5878 */
    { SSL_HND_HELLO_EXT_CERT_TYPE, "cert_type" }, /* RFC 6091 */
    { SSL_HND_HELLO_EXT_SUPPORTED_GROUPS, "supported_groups" }, /* RFC 4492, RFC 7919 */
    { SSL_HND_HELLO_EXT_EC_POINT_FORMATS, "ec_point_formats" }, /* RFC 4492 */
    { SSL_HND_HELLO_EXT_SRP, "srp" }, /* RFC 5054 */
    { SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS, "signature_algorithms" }, /* RFC 5246 */
    { SSL_HND_HELLO_EXT_USE_SRTP, "use_srtp" }, /* RFC 5764 */
    { SSL_HND_HELLO_EXT_HEARTBEAT, "heartbeat" }, /* RFC 6520 */
    { SSL_HND_HELLO_EXT_ALPN, "application_layer_protocol_negotiation" }, /* RFC 7301 */
    { SSL_HND_HELLO_EXT_STATUS_REQUEST_V2, "status_request_v2" }, /* RFC 6961 */
    { SSL_HND_HELLO_EXT_SIGNED_CERTIFICATE_TIMESTAMP, "signed_certificate_timestamp" }, /* RFC 6962 */
    { SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE, "client_certificate_type" }, /* RFC 7250 */
    { SSL_HND_HELLO_EXT_SERVER_CERT_TYPE, "server_certificate_type" }, /* RFC 7250 */
    { SSL_HND_HELLO_EXT_PADDING, "padding" }, /* RFC 7685 */
    { SSL_HND_HELLO_EXT_ENCRYPT_THEN_MAC, "encrypt_then_mac" }, /* RFC 7366 */
    { SSL_HND_HELLO_EXT_EXTENDED_MASTER_SECRET, "extended_master_secret" }, /* RFC 7627 */
    { SSL_HND_HELLO_EXT_TOKEN_BINDING, "token_binding" }, /* https://tools.ietf.org/html/draft-ietf-tokbind-negotiation */
    { SSL_HND_HELLO_EXT_CACHED_INFO, "cached_info" }, /* RFC 7924 */
    { SSL_HND_HELLO_EXT_COMPRESS_CERTIFICATE, "compress_certificate" }, /* https://tools.ietf.org/html/draft-ietf-tls-certificate-compression-03 */
    { SSL_HND_HELLO_EXT_RECORD_SIZE_LIMIT, "record_size_limit" }, /* RFC 8449 */
    { SSL_HND_HELLO_EXT_DELEGATED_CREDENTIALS, "delegated_credentials" }, /* draft-ietf-tls-subcerts-09.txt */
    { SSL_HND_HELLO_EXT_SESSION_TICKET_TLS, "session_ticket" }, /* RFC 5077 / RFC 8447 */
    { SSL_HND_HELLO_EXT_KEY_SHARE_OLD, "Reserved (key_share)" }, /* https://tools.ietf.org/html/draft-ietf-tls-tls13-22 (removed in -23) */
    { SSL_HND_HELLO_EXT_PRE_SHARED_KEY, "pre_shared_key" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_EARLY_DATA, "early_data" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_SUPPORTED_VERSIONS, "supported_versions" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_COOKIE, "cookie" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_PSK_KEY_EXCHANGE_MODES, "psk_key_exchange_modes" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_TICKET_EARLY_DATA_INFO, "Reserved (ticket_early_data_info)" }, /* draft-ietf-tls-tls13-18 (removed in -19) */
    { SSL_HND_HELLO_EXT_CERTIFICATE_AUTHORITIES, "certificate_authorities" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_OID_FILTERS, "oid_filters" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_POST_HANDSHAKE_AUTH, "post_handshake_auth" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS_CERT, "signature_algorithms_cert" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_KEY_SHARE, "key_share" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_CONNECTION_ID, "connection_id" }, /* draft-ietf-tls-dtls-connection-id-07 */
    { SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS_V1, "quic_transport_parameters" }, /* draft-ietf-quic-tls-33 */
    { SSL_HND_HELLO_EXT_GREASE_0A0A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_1A1A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_2A2A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_NPN, "next_protocol_negotiation"}, /* https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html */
    { SSL_HND_HELLO_EXT_GREASE_3A3A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_ALPS, "application_settings" }, /* draft-vvv-tls-alps-01 */
    { SSL_HND_HELLO_EXT_GREASE_4A4A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_5A5A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_6A6A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_CHANNEL_ID_OLD, "channel_id_old" }, /* https://tools.ietf.org/html/draft-balfanz-tls-channelid-00
       https://twitter.com/ericlaw/status/274237352531083264 */
    { SSL_HND_HELLO_EXT_CHANNEL_ID, "channel_id" }, /* https://tools.ietf.org/html/draft-balfanz-tls-channelid-01
       https://code.google.com/p/chromium/codesearch#chromium/src/net/third_party/nss/ssl/sslt.h&l=209 */
    { SSL_HND_HELLO_EXT_RENEGOTIATION_INFO, "renegotiation_info" }, /* RFC 5746 */
    { SSL_HND_HELLO_EXT_GREASE_7A7A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_8A8A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_9A9A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_AAAA, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_BABA, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_CACA, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_DADA, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_EAEA, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_FAFA, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS, "quic_transport_parameters (drafts version)" }, /* https://tools.ietf.org/html/draft-ietf-quic-tls */
    { SSL_HND_HELLO_EXT_ENCRYPTED_SERVER_NAME, "encrypted_server_name" }, /* https://tools.ietf.org/html/draft-ietf-tls-esni-01 */
    { 0, NULL }
};

