#ifndef NGX_HEALTH_DETECT_MODULE_UTILS_H_
#define NGX_HEALTH_DETECT_MODULE_UTILS_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_CHECK_CONNECT_DONE 0x0001
#define NGX_HTTP_CHECK_SEND_DONE 0x0002
#define NGX_HTTP_CHECK_RECV_DONE 0x0004
#define NGX_HTTP_CHECK_ALL_DONE 0x0008

#define NGX_SSL_RANDOM "NGX_HTTP_CHECK_SSL_HELLO\n\n\n\n"
#define NGX_SSL_HANDSHAKE 0x16
#define NGX_SSL_SERVER_HELLO 0x02

#pragma pack(push, 1)
typedef struct {
    u_char major;
    u_char minor;
} ngx_ssl_protocol_version_t;

typedef struct {
    u_char msg_type;
    ngx_ssl_protocol_version_t version;
    uint16_t length;

    u_char handshake_type;
    u_char handshake_length[3];
    ngx_ssl_protocol_version_t hello_version;

    time_t time;
    u_char random[28];

    u_char others[0];
} ngx_ssl_server_hello_t;

#pragma pack()

typedef struct {
    ngx_buf_t send;
    ngx_buf_t recv;
    ngx_uint_t state;
    ngx_http_status_t status;
    size_t padding;
    size_t length;
} ngx_http_check_data_ctx_t;

#define ngx_http_health_sslv3_client_hello_pkt                               \
    "\x16"             /* ContentType         : 0x16 = Hanshake           */ \
    "\x03\x01"         /* ProtocolVersion     : 0x0301 = TLSv1.0          */ \
    "\x00\x6f"         /* ContentLength       : 0x6f bytes after this one */ \
    "\x01"             /* HanshakeType        : 0x01 = CLIENT HELLO       */ \
    "\x00\x00\x6b"     /* HandshakeLength     : 0x6b bytes after this one */ \
    "\x03\x03"         /* Hello Version       : 0x0303 = TLSv1.2          */ \
    "\x00\x00\x00\x00" /* Unix GMT Time (s)   : filled with <now> (@0x0B) */ \
        NGX_SSL_RANDOM /* Random              : must be exactly 28 bytes  */ \
    "\x00"             /* Session ID length   : empty (no session ID)     */ \
    "\x00\x1a"         /* Cipher Suite Length : \x1a bytes after this one */ \
    "\xc0\x2b"                                                               \
    "\xc0\x2f"                                                               \
    "\xcc\xa9"                                                               \
    "\xcc\xa8" /* 13 modern ciphers        */                                \
    "\xc0\x0a"                                                               \
    "\xc0\x09"                                                               \
    "\xc0\x13"                                                               \
    "\xc0\x14"                                                               \
    "\x00\x33"                                                               \
    "\x00\x39"                                                               \
    "\x00\x2f"                                                               \
    "\x00\x35"                                                               \
    "\x00\x0a"                                                               \
    "\x01"     /* Compression Length  : 0x01 = 1 byte for types   */         \
    "\x00"     /* Compression Type    : 0x00 = NULL compression   */         \
    "\x00\x28" /* Extensions length */                                       \
    "\x00\x0a" /* EC extension */                                            \
    "\x00\x08" /* extension length */                                        \
    "\x00\x06" /* curves length */                                           \
    "\x00\x17"                                                               \
    "\x00\x18"                                                               \
    "\x00\x19" /* Three curves */                                            \
    "\x00\x0d" /* Signature extension */                                     \
    "\x00\x18" /* extension length */                                        \
    "\x00\x16" /* hash list length */                                        \
    "\x04\x01"                                                               \
    "\x05\x01"                                                               \
    "\x06\x01"                                                               \
    "\x02\x01" /* 11 hash algorithms */                                      \
    "\x04\x03"                                                               \
    "\x05\x03"                                                               \
    "\x06\x03"                                                               \
    "\x02\x03"                                                               \
    "\x05\x02"                                                               \
    "\x04\x02"                                                               \
    "\x02\x02"

#endif  // NGX_HEALTH_DETECT_MODULE_UTILS_H_