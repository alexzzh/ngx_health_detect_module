#include "cJSON.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_CHECK_TCP 0x0001
#define NGX_HTTP_CHECK_HTTP 0x0002
#define NGX_HTTP_CHECK_SSL_HELLO 0x0004

#define NGX_CHECK_HTTP_2XX 0x0002
#define NGX_CHECK_HTTP_3XX 0x0004
#define NGX_CHECK_HTTP_4XX 0x0008
#define NGX_CHECK_HTTP_5XX 0x0010
#define NGX_CHECK_HTTP_ERR 0x8000

#define NGX_HTTP_CHECK_CONNECT_DONE 0x0001
#define NGX_HTTP_CHECK_SEND_DONE 0x0002
#define NGX_HTTP_CHECK_RECV_DONE 0x0004
#define NGX_HTTP_CHECK_ALL_DONE 0x0008

#define NGX_CHECK_STATUS_INVALID 0x0000
#define NGX_CHECK_STATUS_DOWN 0x0001
#define NGX_CHECK_STATUS_UP 0x0002

#define NGX_SSL_RANDOM "NGX_HTTP_CHECK_SSL_HELLO\n\n\n\n"
#define NGX_SSL_HANDSHAKE 0x16
#define NGX_SSL_SERVER_HELLO 0x02

#define NGX_HTTP_ALERT_METHOD_LOG 0x0001
#define NGX_HTTP_ALERT_METHOD_SYSLOG 0x0002

#define PEER_NAME_LEN_MAX_VALUE 50

#define PEER_CHECK_FALL_RISE_MIN_VALUE 1
#define PEER_CHECK_FALL_RISE_MAX_VALUE 10

#define PEER_CHECK_INTERVAL_MIN_VALUE 100
#define PEER_CHECK_INTERVAL_MAX_VALUE 60 * 1000

#define PEER_CHECK_TIMEOUT_MIN_VALUE 500
#define PEER_CHECK_TIMEOUT_MAX_VALUE 60 * 5 * 1000

#define PEER_CHECK_KEEPALIVE_TIME_MIN_VALUE 10 * 1000
#define PEER_CHECK_KEEPALIVE_TIME_MAX_VALUE 24 * 3600 * 1000

#define MAX_PEER_NUMS_DEFAULT_VALUE 1000
#define MAX_PEER_NUMS_MAX_VALUE 20000

#define MAX_SEND_CONTENT_LEN_MAX_VALUE 500

#define MAX_STATUS_CHANGE_COUNT_DEFAULT_VALUE 10
#define MAX_STATUS_CHANGE_COUNT_MAX_VALUE 100

#define CHECK_SHM_SIZE_MIN_VALUE 1 * 1024 * 1024      /* 1m */
#define CHECK_SHM_SIZE_DEFAULT_VALUE 10 * 1024 * 1024 /* 10m */

static void *ngx_http_health_detect_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_health_detect_merge_srv_conf(ngx_conf_t *cf, void *parent,
                                                   void *child);

typedef struct ngx_http_health_detect_srv_conf_s
    ngx_http_health_detect_srv_conf_t;

typedef struct ngx_http_health_detect_peer_shm_s
    ngx_http_health_detect_peer_shm_t;
typedef struct ngx_http_health_detect_peers_shm_s
    ngx_http_health_detect_peers_shm_t;
typedef struct ngx_http_health_detect_peer_s ngx_http_health_detect_peer_t;
typedef struct ngx_http_health_detect_peers_s ngx_http_health_detect_peers_t;

typedef struct ngx_health_detect_default_detect_policy_s
    ngx_health_detect_default_detect_policy_t;
static ngx_health_detect_default_detect_policy_t *
ngx_http_get_default_detect_policy(ngx_uint_t type);

typedef ngx_int_t (*ngx_http_health_detect_packet_init_pt)(
    ngx_http_health_detect_peer_t *peer);
typedef ngx_int_t (*ngx_http_health_detect_packet_parse_pt)(
    ngx_http_health_detect_peer_t *peer);
typedef void (*ngx_http_health_detect_packet_clean_pt)(
    ngx_http_health_detect_peer_t *peer);

typedef void (*ngx_http_health_detect_one_node_status_format_pt)(
    ngx_buf_t *b, ngx_http_health_detect_peer_shm_t *peer);
typedef void (*ngx_http_health_detect_all_node_status_format_pt)(
    ngx_buf_t *b, ngx_http_health_detect_peers_shm_t *peer);

static void ngx_http_health_detect_all_status_json_format(
    ngx_buf_t *b, ngx_http_health_detect_peers_shm_t *peers);
static void ngx_http_health_detect_status_json_format(
    ngx_buf_t *b, ngx_http_health_detect_peer_shm_t *peer);
static void ngx_http_health_detect_all_status_html_format(
    ngx_buf_t *b, ngx_http_health_detect_peers_shm_t *peers);
static void ngx_http_health_detect_status_html_format(
    ngx_buf_t *b, ngx_http_health_detect_peer_shm_t *peer);

typedef ngx_int_t (*support_op_pt)(ngx_http_request_t *r, void *data);
static void ngx_health_detect_free_node(ngx_rbtree_node_t *node);
static ngx_int_t ngx_health_detect_add_or_update_node(ngx_http_request_t *r,
                                                      void *data);
static ngx_int_t ngx_health_detect_delete_node(ngx_http_request_t *r,
                                               void *data);
static ngx_int_t ngx_health_detect_delete_all_node(ngx_http_request_t *r,
                                                   void *data);

static ngx_int_t ngx_health_detect_check_node_status(ngx_http_request_t *r,
                                                     void *data);
static ngx_int_t ngx_health_detect_check_all_node_status(ngx_http_request_t *r,
                                                         void *data);

static ngx_int_t ngx_parse_addr_port_on_slab_pool_locked(ngx_slab_pool_t *pool,
                                                         ngx_addr_t *addr,
                                                         u_char *text,
                                                         size_t len);

static ngx_int_t ngx_http_health_detect_init(ngx_conf_t *cf);

static void
ngx_http_health_detect_reload_peer_node(ngx_rbtree_node_t *node_shm,
                                        ngx_rbtree_node_t *sentinel);
static ngx_int_t ngx_http_health_detect_add_timers(ngx_rbtree_node_t *node);
static ngx_int_t ngx_http_health_detect_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_health_detect_need_exit();

static ngx_int_t ngx_http_health_detect_status_update(ngx_rbtree_node_t *node,
                                                      ngx_uint_t result);
static void ngx_http_health_detect_clean_timeout_event_and_connection(
    ngx_http_health_detect_peer_t *peer);

static void ngx_http_health_detect_peek_handler(ngx_event_t *event);
static void ngx_http_health_detect_send_handler(ngx_event_t *event);
static void ngx_http_health_detect_recv_handler(ngx_event_t *event);

static ngx_int_t
ngx_http_health_detect_http_init(ngx_http_health_detect_peer_t *peer);
static ngx_int_t
ngx_http_health_detect_http_parse(ngx_http_health_detect_peer_t *peer);
static void
ngx_http_health_detect_http_reinit(ngx_http_health_detect_peer_t *peer);
static void
ngx_http_health_detect_ssl_hello_reinit(ngx_http_health_detect_peer_t *peer);
static ngx_int_t
ngx_http_health_detect_ssl_hello_parse(ngx_http_health_detect_peer_t *peer);
static ngx_int_t
ngx_http_health_detect_ssl_hello_init(ngx_http_health_detect_peer_t *peer);

static void
ngx_http_health_detect_peer_rbtree_insert_value(ngx_rbtree_node_t *temp,
                                                ngx_rbtree_node_t *node,
                                                ngx_rbtree_node_t *sentinel);
static void ngx_http_health_detect_peer_shm_rbtree_insert_value(
    ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);
static ngx_int_t
ngx_health_detect_check_interval_is_valid(ngx_msec_int_t check_interval);
static ngx_int_t
ngx_health_detect_check_timeout_is_valid(ngx_msec_int_t check_timeout);
static ngx_int_t
ngx_health_detect_check_keepalive_time_is_valid(ngx_msec_int_t keepalive_time);

static char *ngx_conf_health_detect_set_max_check_nums(ngx_conf_t *cf,
                                                       ngx_command_t *cmd,
                                                       void *conf);
static char *ngx_conf_health_detect_set_max_history_status_count(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_health_detect_check_zone(ngx_conf_t *cf,
                                               ngx_command_t *cmd, void *conf);

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
  ngx_str_t format;
  ngx_str_t content_type;
  ngx_http_health_detect_one_node_status_format_pt one_node_output;
  ngx_http_health_detect_all_node_status_format_pt all_node_output;
} ngx_http_health_detect_status_format_ctx_t;

typedef struct {
  ngx_buf_t send;
  ngx_buf_t recv;
  ngx_uint_t state;
  ngx_http_status_t status;
  size_t padding;
  size_t length;
} ngx_http_check_data_ctx_t;

typedef struct {
  ngx_str_t access_time;
  ngx_uint_t status;
  ngx_queue_t link;
} ngx_health_detect_one_peer_status;

typedef struct {
  ngx_uint_t latest_status;
  ngx_uint_t max_status_count;
  ngx_uint_t current_status_count;
  ngx_queue_t history_status; /* ngx_health_detect_one_peer_status */
  ngx_str_t latest_access_time;
} ngx_health_detect_peer_status_t;

struct ngx_health_detect_default_detect_policy_s {
  ngx_uint_t type;
  ngx_str_t name;
  ngx_str_t default_send_content;
  ngx_uint_t expect_response_status;
  ngx_str_t alert_method;
  ngx_uint_t fall;
  ngx_uint_t rise;

  ngx_event_handler_pt send_handler;
  ngx_event_handler_pt recv_handler;
  ngx_http_health_detect_packet_init_pt init;
  ngx_http_health_detect_packet_parse_pt parse;
  ngx_http_health_detect_packet_clean_pt reinit;

  unsigned need_pool;

  ngx_uint_t need_keepalive;
  ngx_msec_t keepalive_time;

  ngx_msec_t check_interval;
  ngx_msec_t check_timeout;
};

typedef struct {
  ngx_uint_t type;
  ngx_uint_t alert_method;
  union {
    ngx_uint_t return_code;
    ngx_uint_t http_status;
  } expect_response_status;

  ngx_uint_t fall;
  ngx_uint_t rise;

  ngx_msec_int_t check_interval;
  ngx_msec_int_t check_timeout;

  ngx_uint_t need_keepalive;
  ngx_msec_t keepalive_time;

  ngx_uint_t checksum;
} ngx_health_detect_policy_data_t;

typedef struct {
  ngx_str_t peer_name;
  ngx_addr_t peer_addr;
  ngx_str_t send_content;

  ngx_health_detect_policy_data_t data;
} ngx_health_detect_detect_policy_t;

struct ngx_http_health_detect_peer_shm_s {
  u_char color;

  ngx_shmtx_sh_t lock;
  ngx_pid_t owner;

  ngx_health_detect_detect_policy_t policy;
  ngx_health_detect_peer_status_t status;

  ngx_msec_t access_time;
  ngx_uint_t fall_count;
  ngx_uint_t rise_count;
};

struct ngx_http_health_detect_peer_s {
  u_char color;
  ngx_flag_t state;
  ngx_event_t check_ev;
  ngx_event_t check_timeout_ev;
  ngx_peer_connection_t pc;
  ngx_health_detect_detect_policy_t *policy;
  ngx_pool_t *temp_pool;

  ngx_health_detect_default_detect_policy_t *default_policy;
  void *check_data;
  ngx_pool_t *check_pool;
};

struct ngx_http_health_detect_peers_shm_s {
  ngx_uint_t number;
  ngx_uint_t max_number;

  ngx_rbtree_t rbtree; /* ngx_http_health_detect_peer_shm_t */
  ngx_rbtree_node_t sentinel;

  ngx_slab_pool_t *shpool;
};

struct ngx_http_health_detect_peers_s {
  ngx_rbtree_t rbtree; /* ngx_http_health_detect_peer_t */
  ngx_rbtree_node_t sentinel;
};

typedef struct {
  ngx_event_t reload_timer_ev;

  ngx_http_health_detect_peers_t *peers;
  ngx_http_health_detect_peers_shm_t *peers_shm;

  ngx_http_health_detect_srv_conf_t *hdscf;
} ngx_http_health_detect_peers_manager_t;

ngx_http_health_detect_peers_manager_t *peers_manager_ctx = NULL;

struct ngx_http_health_detect_srv_conf_s {
  ngx_flag_t enable;
  ngx_uint_t max_check_nums;
  ngx_uint_t max_history_status_count;
  ngx_shm_zone_t *check_zone;
};

/*
 * This is the SSLv3 CLIENT HELLO packet used in conjunction with the
 * check type of ssl_hello to ensure that the remote server speaks SSL.
 *
 * Check RFC 2246 (TLSv1.0) sections A.3 and A.4 for details.
 */
static char sslv3_client_hello_pkt[] = {
    "\x16"             /* ContentType         : 0x16 = Hanshake           */
    "\x03\x01"         /* ProtocolVersion     : 0x0301 = TLSv1.0          */
    "\x00\x6f"         /* ContentLength       : 0x6f bytes after this one */
    "\x01"             /* HanshakeType        : 0x01 = CLIENT HELLO       */
    "\x00\x00\x6b"     /* HandshakeLength     : 0x6b bytes after this one */
    "\x03\x03"         /* Hello Version       : 0x0303 = TLSv1.2          */
    "\x00\x00\x00\x00" /* Unix GMT Time (s)   : filled with <now> (@0x0B) */
    NGX_SSL_RANDOM     /* Random              : must be exactly 28 bytes  */
    "\x00"             /* Session ID length   : empty (no session ID)     */
    "\x00\x1a"         /* Cipher Suite Length : \x1a bytes after this one */
    "\xc0\x2b"
    "\xc0\x2f"
    "\xcc\xa9"
    "\xcc\xa8" /* 13 modern ciphers        */
    "\xc0\x0a"
    "\xc0\x09"
    "\xc0\x13"
    "\xc0\x14"
    "\x00\x33"
    "\x00\x39"
    "\x00\x2f"
    "\x00\x35"
    "\x00\x0a"
    "\x01"     /* Compression Length  : 0x01 = 1 byte for types   */
    "\x00"     /* Compression Type    : 0x00 = NULL compression   */
    "\x00\x28" /* Extensions length */
    "\x00\x0a" /* EC extension */
    "\x00\x08" /* extension length */
    "\x00\x06" /* curves length */
    "\x00\x17"
    "\x00\x18"
    "\x00\x19" /* Three curves */
    "\x00\x0d" /* Signature extension */
    "\x00\x18" /* extension length */
    "\x00\x16" /* hash list length */
    "\x04\x01"
    "\x05\x01"
    "\x06\x01"
    "\x02\x01" /* 11 hash algorithms */
    "\x04\x03"
    "\x05\x03"
    "\x06\x03"
    "\x02\x03"
    "\x05\x02"
    "\x04\x02"
    "\x02\x02"};

static ngx_uint_t
ngx_health_detect_get_policy_type_from_string(ngx_str_t *type) {
  if ((type->len == sizeof("tcp") - 1) &&
      (ngx_strncasecmp(type->data, (u_char *)"tcp", type->len) == 0)) {
    return NGX_HTTP_CHECK_TCP;
  } else if ((type->len == sizeof("http") - 1) &&
             (ngx_strncasecmp(type->data, (u_char *)"http", type->len) == 0)) {
    return NGX_HTTP_CHECK_HTTP;
  } else if ((type->len == sizeof("https") - 1) &&
             (ngx_strncasecmp(type->data, (u_char *)"https", type->len) == 0)) {
    return NGX_HTTP_CHECK_SSL_HELLO;
  } else {
    return 0;
  }
}

static char *ngx_health_detect_get_policy_type_to_string(ngx_uint_t type) {
  if (type == NGX_HTTP_CHECK_TCP) {
    return "tcp";
  } else if (type == NGX_HTTP_CHECK_HTTP) {
    return "http";
  } else if (type == NGX_HTTP_CHECK_SSL_HELLO) {
    return "https";
  } else {
    return "";
  }
}

static ngx_uint_t
ngx_health_detect_get_policy_alert_method_from_string(ngx_str_t *type) {
  if ((type->len == sizeof("log") - 1) &&
      (ngx_strncasecmp(type->data, (u_char *)"log", type->len) == 0)) {
    return NGX_HTTP_ALERT_METHOD_LOG;
  } else if ((type->len == sizeof("syslog") - 1) &&
             (ngx_strncasecmp(type->data, (u_char *)"syslog", type->len) ==
              0)) {
    return NGX_HTTP_ALERT_METHOD_SYSLOG;
  } else {
    return 0;
  }
}

static char *
ngx_health_detect_get_policy_alert_method_to_string(ngx_uint_t type) {
  if (type == NGX_HTTP_ALERT_METHOD_LOG) {
    return "log";
  } else if (type == NGX_HTTP_ALERT_METHOD_SYSLOG) {
    return "syslog";
  } else {
    return "";
  }
}

static ngx_health_detect_default_detect_policy_t
    ngx_health_detect_default_detect_policy[] = {
        {
         NGX_HTTP_CHECK_TCP, ngx_string("tcp"), ngx_null_string, 0,
         ngx_string("log"), 1, 2, ngx_http_health_detect_peek_handler,
         ngx_http_health_detect_peek_handler, NULL, NULL, NULL, 0, 0, 100000,
         1000, 3000
        },
        {
          NGX_HTTP_CHECK_HTTP, ngx_string("http"),
         ngx_string("GET / HTTP/1.0\r\n\r\n"),
         NGX_CONF_BITMASK_SET | NGX_CHECK_HTTP_2XX | NGX_CHECK_HTTP_3XX,
         ngx_string("log"), 1, 2, ngx_http_health_detect_send_handler,
         ngx_http_health_detect_recv_handler, ngx_http_health_detect_http_init,
         ngx_http_health_detect_http_parse, ngx_http_health_detect_http_reinit,
         1, 0, 100000, 1000, 3000
        },
        {
         NGX_HTTP_CHECK_SSL_HELLO, ngx_string("https"),
         ngx_string(sslv3_client_hello_pkt), 0, ngx_string("log"), 1, 2,
         ngx_http_health_detect_send_handler,
         ngx_http_health_detect_recv_handler,
         ngx_http_health_detect_ssl_hello_init,
         ngx_http_health_detect_ssl_hello_parse,
         ngx_http_health_detect_ssl_hello_reinit, 1, 0, 0, 1000, 3000
        },
        {
         0, ngx_null_string, ngx_null_string, 0, ngx_null_string, 0, 0,
         NULL,NULL, NULL, NULL, NULL, 0, 0, 0, 1000, 3000
        }
};

#define NGX_PRASE_REQ_OK 0
#define NGX_PRASE_REQ_ERR -1
#define NGX_PRASE_REQ_PEER_NAME_TOO_LONG -2
#define NGX_PRASE_REQ_INVALID_PEER_TYPE -3
#define NGX_PRASE_REQ_PEER_TYPE_NOT_FOUND -4
#define NGX_PRASE_REQ_INVALID_PEER_ADDR -5
#define NGX_PRASE_REQ_PEER_ADDR_NOT_FOUND -6
#define NGX_PRASE_REQ_SEND_CONTENT_TOO_LONG -7
#define NGX_PRASE_REQ_INVALID_ALERT_METHOD -8
#define NGX_PRASE_REQ_INVALID_EXPECT_RESPONSE_STATUS -9
#define NGX_PRASE_REQ_INVALID_CHECK_INTERVAL -10
#define NGX_PRASE_REQ_INVALID_CHECK_TIMEOUT -11
#define NGX_PRASE_REQ_INVALID_CHECK_FALL_RISE_NUMBER -12
#define NGX_PRASE_REQ_NEED_KEEPALIVE_NOT_BOOL -13
#define NGX_PRASE_REQ_INVALID_KEEPALIVE_TIME -14

static ngx_http_health_detect_status_format_ctx_t ngx_check_status_formats[] = {
    {
     ngx_string("json"), ngx_string("application/json"),
     ngx_http_health_detect_status_json_format,
     ngx_http_health_detect_all_status_json_format
    },
    {
     ngx_string("html"), ngx_string("text/html"),
     ngx_http_health_detect_status_html_format,
     ngx_http_health_detect_all_status_html_format
    },
    {
     ngx_null_string, ngx_null_string, NULL, NULL
    }
};

static ngx_conf_bitmask_t ngx_check_http_expect_alive_masks[] = {
    {
     ngx_string("http_2xx"), NGX_CHECK_HTTP_2XX
    },
    {
     ngx_string("http_3xx"), NGX_CHECK_HTTP_3XX
    },
    {
     ngx_string("http_4xx"), NGX_CHECK_HTTP_4XX
    },
    {
     ngx_string("http_5xx"), NGX_CHECK_HTTP_5XX
    },
    {
     ngx_string("http_err"), NGX_CHECK_HTTP_ERR
    },
    {
     ngx_null_string, 0
    }
};

#define ADD_PEER 1
#define UPDATE_PEER 2
#define DELETE_PEER 3
#define DELETE_ALL_PEERS 4
#define CHECK_ONE_PEER_STATUS 5
#define CHECK_ALL_PEER_STATUS_OP 6

typedef struct support_op_s {
  ngx_int_t op_code;
  ngx_str_t op_des;
  support_op_pt op_handler;
} support_op_t;

static support_op_t api_route[] = {
    {
     ADD_PEER, ngx_string("/add/"),
     ngx_health_detect_add_or_update_node
    },
    {
     UPDATE_PEER, ngx_string("/update/"),
     ngx_health_detect_add_or_update_node
    },
    {
     DELETE_PEER, ngx_string("/delete/"),
     ngx_health_detect_delete_node
    },
    {
     DELETE_ALL_PEERS, ngx_string("/delete_all"),
     ngx_health_detect_delete_all_node
    },
    {
     CHECK_ONE_PEER_STATUS, ngx_string("/check_status/"),
     ngx_health_detect_check_node_status
    },
    {
     CHECK_ALL_PEER_STATUS_OP, ngx_string("/check_all_status"),
     ngx_health_detect_check_all_node_status
    },
    {0, ngx_null_string, NULL}
};

static ngx_command_t ngx_http_health_detect_cmds[] = {
    {
     ngx_string("health_detect_enable"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_health_detect_srv_conf_t, enable), NULL
    },
    {
     ngx_string("health_detect_max_check_nums"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_health_detect_set_max_check_nums, NGX_HTTP_SRV_CONF_OFFSET, 0,NULL
    },
    {
     ngx_string("health_detect_max_history_status_count"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_health_detect_set_max_history_status_count,
     NGX_HTTP_SRV_CONF_OFFSET, 0, NULL
    },
    {
     ngx_string("health_detect_check_zone"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_health_detect_check_zone, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_health_detect_modules_ctx = {
    NULL,
    ngx_http_health_detect_init,
    NULL,
    NULL,
    ngx_http_health_detect_create_srv_conf,
    ngx_http_health_detect_merge_srv_conf,
    NULL,
    NULL,
};

ngx_module_t ngx_http_health_detect_module = {
    NGX_MODULE_V1,
    &ngx_http_health_detect_modules_ctx,
    ngx_http_health_detect_cmds,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    ngx_http_health_detect_init_process,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING};

static void *ngx_http_health_detect_create_srv_conf(ngx_conf_t *cf) {
  ngx_http_health_detect_srv_conf_t *hdscf;

  hdscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_health_detect_srv_conf_t));
  if (hdscf == NULL) {
    return NULL;
  }

  hdscf->enable = NGX_CONF_UNSET;
  hdscf->max_check_nums = NGX_CONF_UNSET_UINT;
  hdscf->max_history_status_count = NGX_CONF_UNSET_UINT;
  hdscf->check_zone = NGX_CONF_UNSET_PTR;

  return hdscf;
}

static ngx_int_t
ngx_http_health_detect_check_init_shm_zone(ngx_shm_zone_t *shm_zone,
                                           void *data) {
  ngx_slab_pool_t *shpool;
  ngx_http_health_detect_peers_shm_t *peers_shm, *opeers_shm;
  size_t len;
  ngx_uint_t start;

  if (data != NULL) {
    shm_zone->data = data;

    if (peers_manager_ctx == NULL) {
      return NGX_OK;
    }

    opeers_shm = data;
    peers_manager_ctx->peers_shm = opeers_shm;
    peers_manager_ctx->peers_shm->shpool = opeers_shm->shpool;
    peers_manager_ctx->peers_shm->max_number =
        peers_manager_ctx->hdscf->max_check_nums;

    /* clear all nodes on old zone if new "max_check_nums" value less than nodes counts on old zone */
    if (peers_manager_ctx->peers_shm->number >
        peers_manager_ctx->hdscf->max_check_nums) {
      start = 1;
      ngx_health_detect_delete_all_node(NULL, &start);
    }

    return NGX_OK;
  }

  shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;

  peers_shm =
      ngx_slab_calloc(shpool, sizeof(ngx_http_health_detect_peers_shm_t));
  if (peers_shm == NULL) {
    goto failure;
  }

  len = sizeof(" in health detect shared zone \"\"") + shm_zone->shm.name.len;

  shpool->log_ctx = ngx_slab_alloc(shpool, len);
  if (shpool->log_ctx == NULL) {
    return NGX_ERROR;
  }

  ngx_sprintf(shpool->log_ctx, " in health detect shared zone \"%V\"%Z",
              &shm_zone->shm.name);
  shpool->log_nomem = 0;

  peers_shm->number = 0;
  peers_shm->max_number = peers_manager_ctx->hdscf->max_check_nums;

  ngx_rbtree_init(&peers_shm->rbtree, &peers_shm->sentinel,
                  ngx_http_health_detect_peer_shm_rbtree_insert_value);

  peers_manager_ctx->peers_shm = peers_shm;
  peers_manager_ctx->peers_shm->shpool = shpool;

  shm_zone->data = peers_manager_ctx->peers_shm;

  return NGX_OK;

failure:
  ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                "health_detect check_shm_size is too small, "
                "you should specify a larger size.");

  return NGX_ERROR;
}

static char *ngx_http_health_detect_init_shm(ngx_conf_t *cf,
                                             ngx_str_t *zone_name,
                                             ngx_int_t size) {
  ngx_http_health_detect_srv_conf_t *hdscf;
  ngx_shm_zone_t *check_zone;

  hdscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_health_detect_module);

  check_zone = ngx_shared_memory_add(cf, zone_name, size,
                                     &ngx_http_health_detect_module);
  if (check_zone == NULL) {
    return NGX_CONF_ERROR;
  }

  hdscf->check_zone = check_zone;
  hdscf->check_zone->init = ngx_http_health_detect_check_init_shm_zone;

  ngx_log_error(NGX_LOG_DEBUG, cf->log, 0,
                "health_detect srv conf: check_zone name(%V) size(%ui)M",
                zone_name, size / 1024 / 1024);

  return NGX_CONF_OK;
}

static char *ngx_http_health_detect_merge_srv_conf(ngx_conf_t *cf, void *parent,
                                                   void *child) {
  ngx_http_health_detect_srv_conf_t *prev = parent;
  ngx_http_health_detect_srv_conf_t *conf = child;
  ngx_str_t name;
  ngx_conf_merge_value(conf->enable, prev->enable, 0);
  ngx_conf_merge_uint_value(conf->max_check_nums, prev->max_check_nums,
                            MAX_PEER_NUMS_DEFAULT_VALUE);
  ngx_conf_merge_uint_value(conf->max_history_status_count,
                            prev->max_history_status_count,
                            MAX_STATUS_CHANGE_COUNT_DEFAULT_VALUE);
  ngx_conf_merge_ptr_value(conf->check_zone, prev->check_zone, NULL);

  if (!conf->enable) {
    peers_manager_ctx = NULL;

    ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                  "ngx_http_health_detect_module is not enabled!");
    return NGX_CONF_OK;
  }

  peers_manager_ctx =
      ngx_pcalloc(cf->pool, sizeof(ngx_http_health_detect_peers_manager_t));
  if (peers_manager_ctx == NULL) {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "malloc global peers manager error");
    return NGX_CONF_ERROR;
  }
  peers_manager_ctx->hdscf = conf;

  ngx_log_error(
      NGX_LOG_DEBUG, cf->log, 0,
      "http health detect module srv conf: enable(%ui) max_check_nums(%ui) "
      "max_history_status_count(%ui)",
      conf->enable, conf->max_check_nums, conf->max_history_status_count);

  if (conf->check_zone == NULL) {
    ngx_str_set(&name, "health_detect_check");
    return ngx_http_health_detect_init_shm(cf, &name,
                                           CHECK_SHM_SIZE_DEFAULT_VALUE);
  }

  return NGX_CONF_OK;
}

static char *ngx_conf_health_detect_set_max_check_nums(ngx_conf_t *cf,
                                                       ngx_command_t *cmd,
                                                       void *conf) {
  ngx_str_t *value;

  ngx_http_health_detect_srv_conf_t *hdscf = conf;

  if (hdscf->max_check_nums != NGX_CONF_UNSET_UINT) {
    return "is duplicate";
  }
  value = cf->args->elts;

  hdscf->max_check_nums = ngx_atoi(value[1].data, value[1].len);
  if (hdscf->max_check_nums == (ngx_uint_t)NGX_ERROR ||
      hdscf->max_check_nums < 1 ||
      hdscf->max_check_nums > MAX_PEER_NUMS_MAX_VALUE) {
    ngx_conf_log_error(
        NGX_LOG_EMERG, cf, 0,
        "invalid value \"%s\" in \"%s\" directive, min:%i max: %i",
        value[1].data, cmd->name.data, 1, MAX_PEER_NUMS_MAX_VALUE);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_conf_health_detect_set_max_history_status_count(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_str_t *value;

  ngx_http_health_detect_srv_conf_t *hdscf = conf;

  if (hdscf->max_history_status_count != NGX_CONF_UNSET_SIZE) {
    return "is duplicate";
  }
  value = cf->args->elts;

  hdscf->max_history_status_count = ngx_atoi(value[1].data, value[1].len);
  if (hdscf->max_history_status_count == (ngx_uint_t)NGX_ERROR ||
      hdscf->max_history_status_count > MAX_STATUS_CHANGE_COUNT_MAX_VALUE) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid value \"%s\" in \"%s\" directive, max: %i",
                       value[1].data, cmd->name.data,
                       MAX_STATUS_CHANGE_COUNT_MAX_VALUE);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_health_detect_check_zone(ngx_conf_t *cf,
                                               ngx_command_t *cmd, void *conf) {
  ngx_http_health_detect_srv_conf_t *hdscf = conf;

  size_t len;
  ngx_int_t n;
  ngx_str_t *value, name, size;
  ngx_uint_t j;

  if (hdscf->check_zone != NGX_CONF_UNSET_PTR) {
    return "is duplicate";
  }

  value = cf->args->elts;

  if (value[1].len <= sizeof("shared:") - 1 ||
      ngx_strncmp(value[1].data, "shared:", sizeof("shared:") - 1) != 0) {
    goto invalid;
  }

  len = 0;

  for (j = sizeof("shared:") - 1; j < value[1].len; j++) {
    if (value[1].data[j] == ':') {
      break;
    }

    len++;
  }

  if (len == 0) {
    goto invalid;
  }

  name.len = len;
  name.data = value[1].data + sizeof("shared:") - 1;

  size.len = value[1].len - j - 1;
  size.data = name.data + len + 1;

  n = ngx_parse_size(&size);

  if (n == NGX_ERROR) {
    goto invalid;
  }

  if (n < CHECK_SHM_SIZE_MIN_VALUE) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "http health detect module  zone \"%V\" is too small",
                       &value[1]);

    return NGX_CONF_ERROR;
  }

  return ngx_http_health_detect_init_shm(cf, &name, n);

invalid:
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid http health detect module check zone \"%V\"",
                     &value[1]);
  return NGX_CONF_ERROR;
}

static void ngx_http_health_detect_send_handler(ngx_event_t *event) {
  ssize_t size;
  ngx_connection_t *c;
  ngx_http_health_detect_peer_t *peer;
  ngx_http_check_data_ctx_t *ctx;
  ngx_rbtree_node_t *node;

  if (ngx_http_health_detect_need_exit()) {
    return;
  }

  c = event->data;
  node = c->data;
  peer = (ngx_http_health_detect_peer_t *)(&node->color);

  ngx_log_error(NGX_LOG_DEBUG, event->log, 0, "http check send.");

  if (c->pool == NULL) {
    ngx_log_error(NGX_LOG_ERR, event->log, 0, "check pool NULL with peer: %V ",
                  &peer->policy->peer_addr.name);

    goto check_send_fail;
  }

  if (peer->state != NGX_HTTP_CHECK_CONNECT_DONE) {
    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {

      ngx_log_error(NGX_LOG_ERR, event->log, 0,
                    "check handle write event error with peer: %V ",
                    &peer->policy->peer_addr.name);

      goto check_send_fail;
    }

    return;
  }

  if (peer->check_data == NULL) {
    peer->check_data =
        ngx_pcalloc(peer->check_pool, sizeof(ngx_http_check_data_ctx_t));
    if (peer->check_data == NULL) {
      goto check_send_fail;
    }

    if (peer->default_policy->init == NULL ||
        peer->default_policy->init(peer) != NGX_OK) {

      ngx_log_error(NGX_LOG_ERR, event->log, 0,
                    "check init error with peer: %V ",
                    &peer->policy->peer_addr.name);

      goto check_send_fail;
    }
  }

  ctx = peer->check_data;

  while (ctx->send.pos < ctx->send.last) {

    size = c->send(c, ctx->send.pos, ctx->send.last - ctx->send.pos);

#if (NGX_DEBUG)
    {
      ngx_err_t err;

      err = (size >= 0) ? 0 : ngx_socket_errno;
      ngx_log_error(NGX_LOG_DEBUG, event->log, err,
                    "http check send size: %z, total: %z", size,
                    ctx->send.last - ctx->send.pos);
    }
#endif

    if (size > 0) {
      ctx->send.pos += size;
    } else if (size == 0 || size == NGX_AGAIN) {
      return;
    } else {
      c->error = 1;
      goto check_send_fail;
    }
  }

  if (ctx->send.pos == ctx->send.last) {
    ngx_log_error(NGX_LOG_DEBUG, event->log, 0, "http check send done.");
    peer->state = NGX_HTTP_CHECK_SEND_DONE;
  }

  return;

check_send_fail:
  if (ngx_http_health_detect_status_update(node, NGX_CHECK_STATUS_DOWN) ==
      NGX_DONE) {
    return;
  }
  ngx_http_health_detect_clean_timeout_event_and_connection(peer);
}

static void ngx_http_health_detect_recv_handler(ngx_event_t *event) {
  u_char *new_buf;
  ssize_t size, n;
  ngx_int_t rc;
  ngx_connection_t *c;
  ngx_http_check_data_ctx_t *ctx;
  ngx_http_health_detect_peer_t *peer;
  ngx_rbtree_node_t *node;

  if (ngx_http_health_detect_need_exit()) {
    return;
  }

  c = event->data;
  node = c->data;
  peer = (ngx_http_health_detect_peer_t *)(&node->color);

  if (peer->state != NGX_HTTP_CHECK_SEND_DONE) {

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
      goto check_recv_fail;
    }

    return;
  }

  ctx = peer->check_data;

  if (ctx->recv.start == NULL) {
    ctx->recv.start = ngx_palloc(c->pool, ngx_pagesize / 2);
    if (ctx->recv.start == NULL) {
      goto check_recv_fail;
    }
    ctx->recv.last = ctx->recv.pos = ctx->recv.start;
    ctx->recv.end = ctx->recv.start + ngx_pagesize / 2;
  }

  while (1) {
    n = ctx->recv.end - ctx->recv.last;

    if (n == 0) {
      size = ctx->recv.end - ctx->recv.start;
      new_buf = ngx_palloc(c->pool, size * 2);
      if (new_buf == NULL) {
        goto check_recv_fail;
      }

      ngx_memcpy(new_buf, ctx->recv.start, size);

      ctx->recv.pos = ctx->recv.start = new_buf;
      ctx->recv.last = new_buf + size;
      ctx->recv.end = new_buf + size * 2;

      n = ctx->recv.end - ctx->recv.last;
    }

    size = c->recv(c, ctx->recv.last, n);
    ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "recv size:%z", size);
#if (NGX_DEBUG)
    {
      ngx_err_t err;

      err = (size >= 0) ? 0 : ngx_socket_errno;
      ngx_log_error(NGX_LOG_DEBUG, c->log, err,
                    "http check recv size: %z, peer: %V ", size,
                    &peer->policy.peer_addr.name);
    }
#endif

    if (size > 0) {
      ctx->recv.last += size;
      continue;
    } else if (size == 0 || size == NGX_AGAIN) {
      break;
    } else {
      c->error = 1;
      goto check_recv_fail;
    }
  }

  rc = peer->default_policy->parse(peer);

  ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "http check parse rc: %i, peer: %V ",
                rc, &peer->policy->peer_addr.name);

  switch (rc) {

  case NGX_AGAIN:
    /* The peer has closed its half side of the connection */
    if (size == 0) {
      rc = ngx_http_health_detect_status_update(node, NGX_CHECK_STATUS_DOWN);
      c->error = 1;
    }

    return;

  case NGX_ERROR:
    ngx_log_error(NGX_LOG_ERR, event->log, 0,
                  "check protocol %ui error with peer: %V ",
                  peer->policy->data.type, &peer->policy->peer_addr.name);

    rc = ngx_http_health_detect_status_update(node, NGX_CHECK_STATUS_DOWN);
    break;

  case NGX_OK:
    /* fall through */

  default:
    rc = ngx_http_health_detect_status_update(node, NGX_CHECK_STATUS_UP);
    break;
  }

  peer->state = NGX_HTTP_CHECK_RECV_DONE;
  if (rc != NGX_DONE) {
    ngx_http_health_detect_clean_timeout_event_and_connection(peer);
  }
  return;

check_recv_fail:
  rc = ngx_http_health_detect_status_update(node, NGX_CHECK_STATUS_DOWN);
  if (rc != NGX_DONE) {
    ngx_http_health_detect_clean_timeout_event_and_connection(peer);
  }
}

static void
ngx_health_detect_judge_cond_to_string(char *dst,
                                       ngx_uint_t expect_response_status) {
  if (expect_response_status & NGX_CHECK_HTTP_2XX) {
    strcat(dst, "http_2xx ");
  }
  if (expect_response_status & NGX_CHECK_HTTP_3XX) {
    strcat(dst, "http_3xx ");
  }
  if (expect_response_status & NGX_CHECK_HTTP_4XX) {
    strcat(dst, "http_4xx ");
  }
  if (expect_response_status & NGX_CHECK_HTTP_5XX) {
    strcat(dst, "http_5xx ");
  }
  if (expect_response_status & NGX_CHECK_HTTP_ERR) {
    strcat(dst, "http_err ");
  }
}

static void ngx_http_rbtree_traverse_all_status_json_format(
    ngx_rbtree_node_t *node_shm, ngx_rbtree_node_t *sentinel, ngx_buf_t *b) {
  ngx_http_health_detect_peer_shm_t *peer_shm;

  if (node_shm == sentinel) {
    return;
  }

  ngx_http_rbtree_traverse_all_status_json_format(node_shm->left, sentinel, b);

  peer_shm = (ngx_http_health_detect_peer_shm_t *)(&node_shm->color);
  b->last = ngx_snprintf(
      b->last, b->end - b->last,
      "    {\"name\": \"%V\",\"access_time\": %V, \"status\": \"%s\"}, \n",
      &peer_shm->policy.peer_name, &peer_shm->status.latest_access_time,
      peer_shm->status.latest_status == NGX_CHECK_STATUS_UP ? "up" : "down");

  ngx_http_rbtree_traverse_all_status_json_format(node_shm->right, sentinel, b);
}

static void ngx_http_health_detect_get_down_count(ngx_rbtree_node_t *node_shm,
                                                  ngx_rbtree_node_t *sentinel,
                                                  ngx_uint_t *down_count) {
  ngx_http_health_detect_peer_shm_t *peer_shm;

  if (node_shm == sentinel) {
    return;
  }

  ngx_http_health_detect_get_down_count(node_shm->left, sentinel, down_count);

  peer_shm = (ngx_http_health_detect_peer_shm_t *)(&node_shm->color);
  if (peer_shm->status.latest_status == NGX_CHECK_STATUS_DOWN) {
    *down_count = (*down_count) + 1;
  }

  ngx_http_health_detect_get_down_count(node_shm->right, sentinel, down_count);
}

static void ngx_http_health_detect_all_status_json_format(
    ngx_buf_t *b, ngx_http_health_detect_peers_shm_t *peers_shm) {
  ngx_rbtree_node_t *node_shm, *sentinel;
  ngx_uint_t down_count = 0;

  node_shm = peers_shm->rbtree.root;
  sentinel = peers_shm->rbtree.sentinel;

  ngx_http_health_detect_get_down_count(node_shm, sentinel, &down_count);

  b->last = ngx_snprintf(b->last, b->end - b->last,
                         "{\n\"total\": %ui,\n \"up\": %ui,\n \"down\": %ui,"
                         "\n \"max\": %ui,\n\"items\": [\n",
                         peers_shm->number, peers_shm->number - down_count,
                         down_count, peers_shm->max_number);

  ngx_http_rbtree_traverse_all_status_json_format(node_shm, sentinel, b);

  b->last = ngx_snprintf(b->last, b->end - b->last, "  ]\n");
  b->last = ngx_snprintf(b->last, b->end - b->last, "}\n");
}

static void ngx_http_health_detect_status_json_format(
    ngx_buf_t *b, ngx_http_health_detect_peer_shm_t *peer_shm) {
  ngx_health_detect_one_peer_status *status;
  ngx_queue_t *q;
  char user_define_cond_str[80];

  ngx_memzero(user_define_cond_str, sizeof(user_define_cond_str));
  ngx_health_detect_judge_cond_to_string(
      user_define_cond_str,
      peer_shm->policy.data.expect_response_status.http_status);

  b->last = ngx_snprintf(
      b->last, b->end - b->last,
      "{"
      "\"peer_name\": \"%V\",\n"
      "  \"type\": \"%s\",\n"
      "  \"peer_addr\": \"%V\",\n"
      "  \"send_content\": \"%V\",\n"
      "  \"alert_method\": \"%s\",\n"
      "  \"expect_response_status\": \"%s\",\n"
      "  \"check_interval\": \"%ui\",\n"
      "  \"check_timeout\": \"%ui\",\n"
      "  \"need_keepalive\": \"%ui\",\n"
      "  \"keepalive_time\": \"%ui\",\n"
      "  \"rise\": \"%ui\",\n"
      "  \"fall\": \"%ui\",\n"
      "  \"access_time\": \"%V\",\n"
      "  \"latest_status\": \"%s\",\n"
      "  \"max_status_count\": \"%ui\",\n"
      "  \"history_status\": {\n"
      "    \"current_status_count\": \"%ui\",\n"
      "    \"items\": [\n",
      &peer_shm->policy.peer_name,
      ngx_health_detect_get_policy_type_to_string(peer_shm->policy.data.type),
      &peer_shm->policy.peer_addr.name,
      peer_shm->policy.send_content.len == 0
          ? &ngx_http_get_default_detect_policy(peer_shm->policy.data.type)
                 ->default_send_content
          : &peer_shm->policy.send_content,
      ngx_health_detect_get_policy_alert_method_to_string(
          peer_shm->policy.data.alert_method),
      user_define_cond_str, peer_shm->policy.data.check_interval,
      peer_shm->policy.data.check_timeout, peer_shm->policy.data.need_keepalive,
      peer_shm->policy.data.keepalive_time, peer_shm->policy.data.rise,
      peer_shm->policy.data.fall, &peer_shm->status.latest_access_time,
      peer_shm->status.latest_status == NGX_CHECK_STATUS_UP ? "up" : "down",
      peer_shm->status.max_status_count, peer_shm->status.current_status_count);

  for (q = ngx_queue_head(&peer_shm->status.history_status);
       q != ngx_queue_sentinel(&peer_shm->status.history_status);
       q = ngx_queue_next(q)) {
    status = ngx_queue_data(q, ngx_health_detect_one_peer_status, link);
    b->last =
        ngx_snprintf(b->last, b->end - b->last,
                     "    {\"access_time\": %V, \"status\": \"%s\",} \n",
                     &status->access_time,
                     status->status == NGX_CHECK_STATUS_UP ? "up" : "down");
  }

  b->last = ngx_snprintf(b->last, b->end - b->last, "  ]\n");

  b->last = ngx_snprintf(b->last, b->end - b->last, "}}\n");
}

static void ngx_http_rbtree_traverse_all_status_html_format(
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, ngx_buf_t *b) {
  ngx_http_health_detect_peer_shm_t *peer;

  if (node == sentinel) {
    return;
  }

  ngx_http_rbtree_traverse_all_status_html_format(node->left, sentinel, b);

  peer = (ngx_http_health_detect_peer_shm_t *)(&node->color);
  b->last = ngx_snprintf(
      b->last, b->end - b->last,
      "  <tr  bgcolor=\"#C0C0C0\">\n"
      "<td>%V</td>\n"
      " <td>%V</td>\n"
      " <td>%s</td>\n"
      "  <tr>\n",
      &peer->policy.peer_name, &peer->status.latest_access_time,
      peer->status.latest_status == NGX_CHECK_STATUS_UP ? "up" : "down");

  ngx_http_rbtree_traverse_all_status_html_format(node->right, sentinel, b);
}

static void ngx_http_health_detect_all_status_html_format(
    ngx_buf_t *b, ngx_http_health_detect_peers_shm_t *peers_shm) {
  ngx_rbtree_node_t *node_shm, *sentinel;
  ngx_uint_t down_count = 0;

  node_shm = peers_shm->rbtree.root;
  sentinel = peers_shm->rbtree.sentinel;
  ngx_http_health_detect_get_down_count(node_shm, sentinel, &down_count);

  b->last =
      ngx_snprintf(b->last, b->end - b->last,
                   "<h2>Total: %ui, Up: %ui, Down: %ui, Max: %ui</h2>\n"
                   "<table style=\"background-color:white\" cellspacing=\"0\" "
                   "       cellpadding=\"3\" border=\"1\">\n"
                   "  <tr bgcolor=\"#FFFF00\">\n"
                   "    <td class=\"column\"\">name</td>\n"
                   "    <td class=\"column\"\">access_time</td>\n"
                   "    <td class=\"column\"\">status</td>\n"
                   "  </tr>\n",
                   peers_shm->number, peers_shm->number - down_count,
                   down_count, peers_shm->max_number);

  ngx_http_rbtree_traverse_all_status_html_format(node_shm, sentinel, b);

  b->last = ngx_snprintf(b->last, b->end - b->last,
                         "</table>\n"
                         "</body>\n"
                         "</html>\n");
}

static void ngx_http_health_detect_status_html_format(
    ngx_buf_t *b, ngx_http_health_detect_peer_shm_t *peer_shm) {
  ngx_health_detect_one_peer_status *status;
  ngx_queue_t *q;
  char user_define_cond_str[80];

  ngx_memzero(user_define_cond_str, sizeof(user_define_cond_str));
  ngx_health_detect_judge_cond_to_string(
      user_define_cond_str,
      peer_shm->policy.data.expect_response_status.http_status);

  b->last = ngx_snprintf(
      b->last, b->end - b->last,
      "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\n"
      "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
      "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"
      "<head>\n"
      "  <title>Nginx http health detect status "
      "style=\"background-color:red\" </title>\n"
      "</head>\n"
      "<body>\n"
      "<h1>Nginx http health detect status</h1>\n"
      "<h2>Peer_name : %V,  Type: %s,  Peer_addr: %V</h2>\n"
      "<table style=\"background-color:white\" cellspacing=\"0\" "
      "       cellpadding=\"3\" border=\"1\">\n"
      "  <tr bgcolor=\"#FFFF00\">\n"
      "    <th>send_content</th>\n"
      "    <th>alert_method</th>\n"
      "    <th>expect_response_status</th>\n"
      "    <th>check_interval</th>\n"
      "    <th>check_timeout</th>\n"
      "    <th>need_keepalive</th>\n"
      "    <th>keepalive_time</th>\n"
      "    <th>rise</th>\n"
      "    <th>fall</th>\n"
      "    <th>latest_access_time</th>\n"
      "    <th>latest_status</th>\n"
      "    <th>max_status_count</th>\n"
      "  </tr>\n",
      &peer_shm->policy.peer_name,
      ngx_health_detect_get_policy_type_to_string(peer_shm->policy.data.type),
      &peer_shm->policy.peer_addr.name);

  b->last = ngx_snprintf(
      b->last, b->end - b->last,
      "  <tr  bgcolor=\"#C0C0C0\">\n"
      "    <td>%V</td>\n"
      "    <td>%s</td>\n"
      "    <td>%s</td>\n"
      "    <td>%ui</td>\n"
      "    <td>%ui</td>\n"
      "    <td>%ui</td>\n"
      "    <td>%ui</td>\n"
      "    <td>%ui</td>\n"
      "    <td>%ui</td>\n"
      "    <td>%V</td>\n"
      "    <td>%s</td>\n"
      "    <td>%ui</td>\n"
      "  </tr>\n",
      peer_shm->policy.send_content.len == 0
          ? &ngx_http_get_default_detect_policy(peer_shm->policy.data.type)
                 ->default_send_content
          : &peer_shm->policy.send_content,
      ngx_health_detect_get_policy_alert_method_to_string(
          peer_shm->policy.data.alert_method),
      user_define_cond_str, peer_shm->policy.data.check_interval,
      peer_shm->policy.data.check_timeout, peer_shm->policy.data.need_keepalive,
      peer_shm->policy.data.keepalive_time, peer_shm->policy.data.rise,
      peer_shm->policy.data.fall, &peer_shm->status.latest_access_time,
      peer_shm->status.latest_status == NGX_CHECK_STATUS_UP ? "up" : "down",
      peer_shm->status.max_status_count);

  b->last = ngx_snprintf(b->last, b->end - b->last, "</table>\n");

  b->last =
      ngx_snprintf(b->last, b->end - b->last,
                   "<h2>History status count: %ui</h2>\n"
                   "<table style=\"background-color:white\" cellspacing=\"0\" "
                   "       cellpadding=\"3\" border=\"1\">\n"
                   "  <tr bgcolor=\"#FFFF00\">\n"
                   "    <td class=\"column\"\">access_time</td>\n"
                   "    <td class=\"column\"\">status</td>\n"
                   "  </tr>\n",
                   peer_shm->status.current_status_count);

  for (q = ngx_queue_head(&peer_shm->status.history_status);
       q != ngx_queue_sentinel(&peer_shm->status.history_status);
       q = ngx_queue_next(q)) {
    status = ngx_queue_data(q, ngx_health_detect_one_peer_status, link);
    b->last =
        ngx_snprintf(b->last, b->end - b->last,
                     "  <tr  bgcolor=\"#C0C0C0\">\n"
                     "<td>%V</td>\n"
                     " <td>%s</td>\n"
                     "  <tr>\n",
                     &status->access_time,
                     status->status == NGX_CHECK_STATUS_UP ? "up" : "down");
  }

  b->last = ngx_snprintf(b->last, b->end - b->last,
                         "</table>\n"
                         "</body>\n"
                         "</html>\n");
}

static ngx_int_t ngx_http_health_detect_parse_status_line(
    ngx_http_check_data_ctx_t *ctx, ngx_buf_t *b, ngx_http_status_t *status) {
  u_char ch, *p;
  enum {
    sw_start = 0,
    sw_H,
    sw_HT,
    sw_HTT,
    sw_HTTP,
    sw_first_major_digit,
    sw_major_digit,
    sw_first_minor_digit,
    sw_minor_digit,
    sw_status,
    sw_space_after_status,
    sw_status_text,
    sw_almost_done
  } state;

  state = ctx->state;

  for (p = b->pos; p < b->last; p++) {
    ch = *p;

    switch (state) {

    /* "HTTP/" */
    case sw_start:
      if (ch != 'H') {
        return NGX_ERROR;
      }

      state = sw_H;
      break;

    case sw_H:
      if (ch != 'T') {
        return NGX_ERROR;
      }

      state = sw_HT;
      break;

    case sw_HT:
      if (ch != 'T') {
        return NGX_ERROR;
      }

      state = sw_HTT;
      break;

    case sw_HTT:
      if (ch != 'P') {
        return NGX_ERROR;
      }

      state = sw_HTTP;
      break;

    case sw_HTTP:
      if (ch != '/') {
        return NGX_ERROR;
      }

      state = sw_first_major_digit;
      break;

      /* the first digit of major HTTP version */
    case sw_first_major_digit:
      if (ch < '1' || ch > '9') {
        return NGX_ERROR;
      }

      state = sw_major_digit;
      break;

      /* the major HTTP version or dot */
    case sw_major_digit:
      if (ch == '.') {
        state = sw_first_minor_digit;
        break;
      }

      if (ch < '0' || ch > '9') {
        return NGX_ERROR;
      }

      break;

      /* the first digit of minor HTTP version */
    case sw_first_minor_digit:
      if (ch < '0' || ch > '9') {
        return NGX_ERROR;
      }

      state = sw_minor_digit;
      break;

      /* the minor HTTP version or the end of the request line */
    case sw_minor_digit:
      if (ch == ' ') {
        state = sw_status;
        break;
      }

      if (ch < '0' || ch > '9') {
        return NGX_ERROR;
      }

      break;

      /* HTTP status code */
    case sw_status:
      if (ch == ' ') {
        break;
      }

      if (ch < '0' || ch > '9') {
        return NGX_ERROR;
      }

      status->code = status->code * 10 + ch - '0';

      if (++status->count == 3) {
        state = sw_space_after_status;
        status->start = p - 2;
      }

      break;

      /* space or end of line */
    case sw_space_after_status:
      switch (ch) {
      case ' ':
        state = sw_status_text;
        break;
      case '.': /* IIS may send 403.1, 403.2, etc */
        state = sw_status_text;
        break;
      case CR:
        state = sw_almost_done;
        break;
      case LF:
        goto done;
      default:
        return NGX_ERROR;
      }
      break;

      /* any text until end of line */
    case sw_status_text:
      switch (ch) {
      case CR:
        state = sw_almost_done;

        break;
      case LF:
        goto done;
      }
      break;

      /* end of status line */
    case sw_almost_done:
      status->end = p - 1;
      if (ch == LF) {
        goto done;
      } else {
        return NGX_ERROR;
      }
    }
  }

  b->pos = p;
  ctx->state = state;

  return NGX_AGAIN;

done:

  b->pos = p + 1;

  if (status->end == NULL) {
    status->end = p;
  }

  ctx->state = sw_start;

  return NGX_OK;
}

static ngx_int_t
ngx_http_health_detect_http_parse(ngx_http_health_detect_peer_t *peer) {
  ngx_int_t rc;
  ngx_uint_t code, code_n;
  ngx_http_check_data_ctx_t *ctx;

  ctx = peer->check_data;

  if ((ctx->recv.last - ctx->recv.pos) > 0) {

    rc =
        ngx_http_health_detect_parse_status_line(ctx, &ctx->recv, &ctx->status);
    if (rc == NGX_AGAIN) {
      return rc;
    }

    if (rc == NGX_ERROR) {
      ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "http parse status line error with peer: %V ",
                    &peer->policy->peer_addr.name);
      return rc;
    }

    code = ctx->status.code;

    if (code >= 200 && code < 300) {
      code_n = NGX_CHECK_HTTP_2XX;
    } else if (code >= 300 && code < 400) {
      code_n = NGX_CHECK_HTTP_3XX;
    } else if (code >= 400 && code < 500) {
      peer->pc.connection->error = 1;
      code_n = NGX_CHECK_HTTP_4XX;
    } else if (code >= 500 && code < 600) {
      peer->pc.connection->error = 1;
      code_n = NGX_CHECK_HTTP_5XX;
    } else {
      peer->pc.connection->error = 1;
      code_n = NGX_CHECK_HTTP_ERR;
    }

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                  "http_parse: code_n: %ui, expected http status: %ui", code_n,
                  peer->policy->data.expect_response_status.http_status);

    if (code_n & peer->policy->data.expect_response_status.http_status) {
      return NGX_OK;
    } else {
      return NGX_ERROR;
    }
  } else {
    return NGX_AGAIN;
  }
}

static void
ngx_http_health_detect_http_reinit(ngx_http_health_detect_peer_t *peer) {
  ngx_http_check_data_ctx_t *ctx;

  ctx = peer->check_data;

  ctx->send.pos = ctx->send.start;
  ctx->send.last = ctx->send.end;

  ctx->recv.pos = ctx->recv.last = ctx->recv.start;

  ctx->state = 0;

  ngx_memzero(&ctx->status, sizeof(ngx_http_status_t));
}

static ngx_int_t
ngx_http_health_detect_http_init(ngx_http_health_detect_peer_t *peer) {
  ngx_http_check_data_ctx_t *ctx;

  ctx = peer->check_data;

  if (peer->policy->send_content.len == 0) {
    ctx->send.start = ctx->send.pos =
        (u_char *)peer->default_policy->default_send_content.data;
    ctx->send.end = ctx->send.last =
        ctx->send.start + peer->default_policy->default_send_content.len;

  } else {
    ctx->send.start = ctx->send.pos = (u_char *)peer->policy->send_content.data;
    ctx->send.end = ctx->send.last =
        ctx->send.start + peer->policy->send_content.len;
  }

  ctx->recv.start = ctx->recv.pos = NULL;
  ctx->recv.end = ctx->recv.last = NULL;

  ctx->state = 0;

  ngx_memzero(&ctx->status, sizeof(ngx_http_status_t));

  return NGX_OK;
}

static ngx_int_t
ngx_http_health_detect_ssl_hello_init(ngx_http_health_detect_peer_t *peer) {
  ngx_http_check_data_ctx_t *ctx;

  ctx = peer->check_data;

  if (peer->policy->send_content.len == 0) {
    ctx->send.start = ctx->send.pos =
        (u_char *)peer->default_policy->default_send_content.data;
    ctx->send.end = ctx->send.last =
        ctx->send.start + peer->default_policy->default_send_content.len;

  } else {
    ctx->send.start = ctx->send.pos = (u_char *)peer->policy->send_content.data;
    ctx->send.end = ctx->send.last =
        ctx->send.start + peer->policy->send_content.len;
  }

  ctx->recv.start = ctx->recv.pos = NULL;
  ctx->recv.end = ctx->recv.last = NULL;

  return NGX_OK;
}

static ngx_int_t
ngx_http_health_detect_ssl_hello_parse(ngx_http_health_detect_peer_t *peer) {
  size_t size;
  ngx_ssl_server_hello_t *resp;
  ngx_http_check_data_ctx_t *ctx;

  ctx = peer->check_data;

  size = ctx->recv.last - ctx->recv.pos;
  if (size < sizeof(ngx_ssl_server_hello_t)) {
    return NGX_AGAIN;
  }

  resp = (ngx_ssl_server_hello_t *)ctx->recv.pos;

  ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                "http check ssl_parse, type: %xd, version: %xd.%xd, "
                "length: %xd, handshanke_type: %xd, hello_version: %xd.%xd",
                resp->msg_type, resp->version.major, resp->version.minor,
                ntohs(resp->length), resp->handshake_type,
                resp->hello_version.major, resp->hello_version.minor);

  if (resp->msg_type != NGX_SSL_HANDSHAKE) {
    return NGX_ERROR;
  }

  if (resp->handshake_type != NGX_SSL_SERVER_HELLO) {
    return NGX_ERROR;
  }

  return NGX_OK;
}

static void
ngx_http_health_detect_ssl_hello_reinit(ngx_http_health_detect_peer_t *peer) {
  ngx_http_check_data_ctx_t *ctx;

  ctx = peer->check_data;

  ctx->send.pos = ctx->send.start;
  ctx->send.last = ctx->send.end;

  ctx->recv.pos = ctx->recv.last = ctx->recv.start;
}

static void ngx_http_health_detect_clear_one_peer_all_events(
    ngx_http_health_detect_peer_t *peer) {
  ngx_connection_t *c;

  ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                "clear peer name(%V) all events", &peer->policy->peer_name);

  c = peer->pc.connection;
  if (c) {
    ngx_close_connection(c);
    peer->pc.connection = NULL;
  }

  if (peer->check_ev.timer_set) {
    ngx_del_timer(&peer->check_ev);
  }

  if (peer->check_timeout_ev.timer_set) {
    ngx_del_timer(&peer->check_timeout_ev);
  }

  if (peer->check_pool != NULL) {
    ngx_destroy_pool(peer->check_pool);
    peer->check_pool = NULL;
  }
}

static void ngx_http_health_detect_clear_peers_events() {
  ngx_rbtree_node_t *node;
  ngx_rbtree_node_t *sentinel;
  ngx_http_health_detect_peers_t *peers;

  ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "clear all the events on %P ",
                ngx_pid);

  peers = peers_manager_ctx->peers;

  node = peers->rbtree.root;
  sentinel = peers->rbtree.sentinel;
  while (node != sentinel) {
    ngx_health_detect_free_node(node);

    node = peers->rbtree.root;
  }
}

static ngx_int_t ngx_http_health_detect_need_exit() {
  if (ngx_terminate || ngx_exiting || ngx_quit) {
    ngx_http_health_detect_clear_peers_events();
    return 1;
  }

  return 0;
}

static void ngx_http_health_detect_discard_handler(ngx_event_t *event) {
  u_char buf[4096];
  ssize_t size;
  ngx_connection_t *c;
  ngx_http_health_detect_peer_t *peer;
  ngx_rbtree_node_t *node;

  if (ngx_http_health_detect_need_exit()) {
    return;
  }

  c = event->data;

  node = c->data;
  peer = (ngx_http_health_detect_peer_t *)(&node->color);

  ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "upstream check discard handler on peer_name(%V)",
                &peer->policy->peer_name);

  if (c->close) {
    goto check_discard_fail;
  }

  while (1) {
    size = c->recv(c, buf, 4096);

    if (size > 0) {
      continue;

    } else if (size == NGX_AGAIN) {
      break;

    } else {
      if (size == 0) {
        ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
                      "peer closed its half side of the connection");
      }

      goto check_discard_fail;
    }
  }

  if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
    goto check_discard_fail;
  }

  return;

check_discard_fail:
  c->error = 1;
  ngx_http_health_detect_clean_timeout_event_and_connection(peer);
}

static void ngx_http_health_detect_dummy_handler(ngx_event_t *event) { return; }

static void ngx_http_health_detect_clean_timeout_event_and_connection(
    ngx_http_health_detect_peer_t *peer) {
  ngx_connection_t *c;
  c = peer->pc.connection;

  if (c) {
    if (c->error == 0 && peer->policy->data.need_keepalive &&
        (ngx_current_msec - peer->pc.start_time <
         peer->policy->data.keepalive_time)) {
      c->write->handler = ngx_http_health_detect_dummy_handler;
      c->read->handler = ngx_http_health_detect_discard_handler;
    } else {
      ngx_close_connection(c);
      peer->pc.connection = NULL;
      ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "on clean timeout event and connection:close connection");
    }
  }

  if (peer->check_timeout_ev.timer_set) {
    ngx_del_timer(&peer->check_timeout_ev);
  }

  peer->state = NGX_HTTP_CHECK_ALL_DONE;

  if (peer->check_data != NULL && peer->default_policy->reinit) {
    peer->default_policy->reinit(peer);
  }
}

static void
ngx_http_health_detect_peer_rbtree_insert_value(ngx_rbtree_node_t *temp,
                                                ngx_rbtree_node_t *node,
                                                ngx_rbtree_node_t *sentinel) {
  ngx_rbtree_node_t **p;
  ngx_http_health_detect_peer_t *lrn, *lrnt;

  for (;;) {

    if (node->key < temp->key) {

      p = &temp->left;

    } else if (node->key > temp->key) {

      p = &temp->right;

    } else { /* node->key == temp->key */

      lrn = (ngx_http_health_detect_peer_t *)&node->color;
      lrnt = (ngx_http_health_detect_peer_t *)&temp->color;

      p = (ngx_memn2cmp(
               lrn->policy->peer_name.data, lrnt->policy->peer_name.data,
               lrn->policy->peer_name.len, lrnt->policy->peer_name.len) < 0)
              ? &temp->left
              : &temp->right;
    }

    if (*p == sentinel) {
      break;
    }

    temp = *p;
  }

  *p = node;
  node->parent = temp;
  node->left = sentinel;
  node->right = sentinel;
  ngx_rbt_red(node);
}

static ngx_rbtree_node_t *
ngx_http_health_detect_peers_rbtree_lookup(uint32_t hash, ngx_str_t *key) {
  ngx_rbtree_node_t *node, *sentinel;
  ngx_http_health_detect_peer_t *peer;
  ngx_http_health_detect_peers_t *peers;

  peers = peers_manager_ctx->peers;

  node = peers->rbtree.root;
  sentinel = peers->rbtree.sentinel;

  while (node != sentinel) {
    if (node->key != hash) {
      node = (node->key > hash) ? node->left : node->right;
      continue;
    }

    peer = (ngx_http_health_detect_peer_t *)&node->color;
    if (peer->policy->peer_name.len != key->len) {
      node =
          (peer->policy->peer_name.len < key->len) ? node->left : node->right;
      continue;
    }

    /* hash == node->key */
    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                  "compare node key:%V addr:%V type:%ui", key,
                  &peer->policy->peer_addr.name, peer->policy->data.type);
    ngx_int_t rc =
        ngx_memcmp(peer->policy->peer_name.data, key->data, key->len);
    if (rc == 0) {
      return node;
    }
    node = (rc > 0) ? node->left : node->right;
  }

  return NULL;
}

static void ngx_http_health_detect_peer_shm_rbtree_insert_value(
    ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel) {
  ngx_rbtree_node_t **p;
  ngx_http_health_detect_peer_shm_t *lrn, *lrnt;

  for (;;) {

    if (node->key < temp->key) {

      p = &temp->left;

    } else if (node->key > temp->key) {

      p = &temp->right;

    } else { /* node->key == temp->key */

      lrn = (ngx_http_health_detect_peer_shm_t *)&node->color;
      lrnt = (ngx_http_health_detect_peer_shm_t *)&temp->color;

      p = (ngx_memn2cmp(lrn->policy.peer_name.data, lrnt->policy.peer_name.data,
                        lrn->policy.peer_name.len,
                        lrnt->policy.peer_name.len) < 0)
              ? &temp->left
              : &temp->right;
    }

    if (*p == sentinel) {
      break;
    }

    temp = *p;
  }

  *p = node;
  node->parent = temp;
  node->left = sentinel;
  node->right = sentinel;
  ngx_rbt_red(node);
}

static ngx_rbtree_node_t *
ngx_http_health_detect_peers_shm_rbtree_lookup(uint32_t hash, ngx_str_t *key) {
  ngx_rbtree_node_t *node_shm, *sentinel;
  ngx_http_health_detect_peer_shm_t *peer_shm;
  ngx_http_health_detect_peers_shm_t *peers_shm;

  peers_shm = peers_manager_ctx->peers_shm;

  node_shm = peers_shm->rbtree.root;
  sentinel = peers_shm->rbtree.sentinel;

  while (node_shm != sentinel) {
    if (node_shm->key != hash) {
      node_shm = (node_shm->key > hash) ? node_shm->left : node_shm->right;
      continue;
    }

    peer_shm = (ngx_http_health_detect_peer_shm_t *)&node_shm->color;
    if (peer_shm->policy.peer_name.len != key->len) {
      node_shm = (peer_shm->policy.peer_name.len < key->len) ? node_shm->left
                                                             : node_shm->right;
      continue;
    }

    /* hash == node->key */
    ngx_int_t rc =
        ngx_memcmp(peer_shm->policy.peer_name.data, key->data, key->len);
    if (rc == 0) {
      return node_shm;
    }
    node_shm = (rc > 0) ? node_shm->left : node_shm->right;
  }

  return NULL;
}

static void ngx_health_detect_shm_free_node(ngx_rbtree_node_t *node) {
  ngx_slab_pool_t *shpool;
  ngx_http_health_detect_peers_shm_t *peers_shm;
  ngx_queue_t *q;
  ngx_health_detect_one_peer_status *status;
  ngx_http_health_detect_peer_shm_t *peer_shm;

  peers_shm = peers_manager_ctx->peers_shm;
  shpool = peers_shm->shpool;

  peer_shm = (ngx_http_health_detect_peer_shm_t *)&node->color;

  if (peer_shm->policy.peer_name.data != NULL) {
    ngx_slab_free_locked(shpool, peer_shm->policy.peer_name.data);
  }
  if (peer_shm->policy.peer_addr.name.data != NULL) {
    ngx_slab_free_locked(shpool, peer_shm->policy.peer_addr.name.data);
  }
  if (peer_shm->policy.peer_addr.sockaddr != NULL) {
    ngx_slab_free_locked(shpool, peer_shm->policy.peer_addr.sockaddr);
  }
  if (peer_shm->policy.send_content.data != NULL) {
    ngx_slab_free_locked(shpool, peer_shm->policy.send_content.data);
  }

  if (peer_shm->status.latest_access_time.data != NULL) {
    ngx_slab_free_locked(shpool, peer_shm->status.latest_access_time.data);
  }

  for (q = ngx_queue_head(&peer_shm->status.history_status);
       q != ngx_queue_sentinel(&peer_shm->status.history_status);) {
    status = ngx_queue_data(q, ngx_health_detect_one_peer_status, link);
    q = ngx_queue_next(q);
    ngx_slab_free_locked(shpool, status->access_time.data);
    ngx_slab_free_locked(shpool, status);
  }

  ngx_rbtree_delete(&peers_shm->rbtree, node);

  peers_shm->number--;

  ngx_slab_free_locked(shpool, node);
}

static ngx_int_t ngx_health_detect_add_or_update_node_on_shm(
    ngx_health_detect_detect_policy_t *policy) {
  ngx_slab_pool_t *shpool;
  ngx_http_health_detect_peers_shm_t *peers_shm;
  uint32_t hash;
  ngx_rbtree_node_t *node_shm;
  ngx_http_health_detect_peer_shm_t *peer_shm;
  ngx_int_t rc;
  ngx_http_health_detect_srv_conf_t *hdscf;

  if (peers_manager_ctx == NULL) {
    return NGX_ERROR;
  }

  hdscf = peers_manager_ctx->hdscf;

  peers_shm = peers_manager_ctx->peers_shm;
  shpool = peers_shm->shpool;

  hash = ngx_crc32_short(policy->peer_name.data, policy->peer_name.len);
  ngx_shmtx_lock(&shpool->mutex);
  node_shm =
      ngx_http_health_detect_peers_shm_rbtree_lookup(hash, &policy->peer_name);
  if (node_shm != NULL) {
    peer_shm = (ngx_http_health_detect_peer_shm_t *)&node_shm->color;
    if (peer_shm->policy.data.checksum == policy->data.checksum) {
      ngx_shmtx_unlock(&shpool->mutex);
      ngx_log_error(
          NGX_LOG_WARN, ngx_cycle->log, 0,
          "on shm: op(add/update) node peer name(%V) already exist and "
          "policy is same, so do nothing",
          &policy->peer_name);
      return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                  "on shm: op(add/update) node peer name(%V) already exist but "
                  "policy id diff, so delete old node then add node",
                  &policy->peer_name);
    ngx_health_detect_shm_free_node(node_shm);
  }

  if (peers_shm->number >= peers_shm->max_number) {
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                  "on shm: op(add/update) the number of nodes(%ui) being "
                  "checked exceeds the upper limit(%ui)",
                  peers_shm->number, hdscf->max_check_nums);
    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_ERROR;
  }

  size_t size = offsetof(ngx_rbtree_node_t, color) +
                sizeof(ngx_http_health_detect_peer_shm_t);

  node_shm = ngx_slab_calloc_locked(shpool, size);
  if (node_shm == NULL) {
    goto failed;
  }
  node_shm->key = hash;

  peer_shm = (ngx_http_health_detect_peer_shm_t *)&node_shm->color;

  peer_shm->policy.data = policy->data;

  rc = ngx_parse_addr_port_on_slab_pool_locked(
      shpool, &peer_shm->policy.peer_addr, policy->peer_addr.name.data,
      policy->peer_addr.name.len);
  if (rc == NGX_ERROR || rc == NGX_DECLINED) {
    goto failed;
  }

  peer_shm->policy.peer_name.data =
      ngx_slab_calloc_locked(shpool, policy->peer_name.len);
  if (peer_shm->policy.peer_name.data == NULL) {
    goto failed;
  }
  ngx_memcpy(peer_shm->policy.peer_name.data, policy->peer_name.data,
             policy->peer_name.len);
  peer_shm->policy.peer_name.len = policy->peer_name.len;

  if (policy->send_content.len != 0) {
    peer_shm->policy.send_content.data =
        ngx_slab_calloc_locked(shpool, policy->send_content.len);
    if (peer_shm->policy.send_content.data == NULL) {
      goto failed;
    }
    ngx_memcpy(peer_shm->policy.send_content.data, policy->send_content.data,
               policy->send_content.len);
    peer_shm->policy.send_content.len = policy->send_content.len;
  } else {
    ngx_str_null(&peer_shm->policy.send_content);
  }

  ngx_queue_init(&peer_shm->status.history_status);

  peer_shm->fall_count = 0;
  peer_shm->rise_count = 0;

  peer_shm->status.latest_access_time.len = ngx_cached_err_log_time.len;
  peer_shm->status.latest_access_time.data =
      ngx_slab_calloc_locked(shpool, peer_shm->status.latest_access_time.len);
  if (peer_shm->status.latest_access_time.data == NULL) {
    goto failed;
  }

  ngx_memcpy(peer_shm->status.latest_access_time.data,
             ngx_cached_err_log_time.data, ngx_cached_err_log_time.len);

  peer_shm->status.latest_status = NGX_CHECK_STATUS_INVALID;
  peer_shm->status.max_status_count = hdscf->max_history_status_count;
  peer_shm->status.current_status_count = 0;

  peer_shm->owner = NGX_INVALID_PID;
  peer_shm->access_time = ngx_current_msec;
  ngx_rbtree_insert(&peers_shm->rbtree, node_shm);
  peers_shm->number++;
  ngx_shmtx_unlock(&shpool->mutex);

  ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                "on shm: op(add/update) add node peer name(%V) peer addr(%V)",
                &policy->peer_name, &policy->peer_addr.name);
  return NGX_OK;

failed:
  if (node_shm) {
    ngx_health_detect_shm_free_node(node_shm);
  }

  ngx_shmtx_unlock(&shpool->mutex);

  ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                "on shm: op(add/update) node peer name(%V) failed",
                &policy->peer_name);

  return NGX_ERROR;
}

static ngx_int_t ngx_health_detect_add_or_update_node_on_local(
    ngx_health_detect_detect_policy_t *policy) {
  uint32_t hash;
  ngx_http_health_detect_peer_t *opeer;
  ngx_int_t rc;
  ngx_rbtree_node_t *node;
  ngx_http_health_detect_peer_t *peer;
  size_t peer_size, peer_policy_max_size;
  ngx_pool_t *temp_pool;

  if (peers_manager_ctx == NULL) {
    return NGX_ERROR;
  }

  hash = ngx_crc32_short(policy->peer_name.data, policy->peer_name.len);
  node = ngx_http_health_detect_peers_rbtree_lookup(hash, &policy->peer_name);
  if (node != NULL) {
    opeer = (ngx_http_health_detect_peer_t *)&node->color;
    if (opeer->policy->data.checksum == policy->data.checksum) {
      ngx_log_error(
          NGX_LOG_WARN, ngx_cycle->log, 0,
          "on local: op(add/update) node peer name(%V) already exist and "
          "policy is same, so do nothing",
          &policy->peer_name);

      return NGX_OK;
    }

    ngx_log_error(
        NGX_LOG_WARN, ngx_cycle->log, 0,
        "on local: op(add/update) node peer name(%V) already exist but "
        "policy id diff, so delete old node then add node",
        &policy->peer_name);
    ngx_health_detect_free_node(node);
  }

  peer_size = offsetof(ngx_rbtree_node_t, color) +
              sizeof(ngx_http_health_detect_peer_t);
  peer_policy_max_size = sizeof(ngx_health_detect_detect_policy_t) +
                         sizeof(ngx_sockaddr_t) /*sockaddr len*/ +
                         NGX_SOCKADDR_STRLEN /*addr name*/ + sizeof("https") -
                         1 /*type*/ + PEER_NAME_LEN_MAX_VALUE /*peer_name*/ +
                         MAX_SEND_CONTENT_LEN_MAX_VALUE /*send_content*/ +
                         sizeof("syslog") - 1 /*alert method*/;

  temp_pool = ngx_create_pool(
      ngx_align(peer_size + peer_policy_max_size, ngx_cacheline_size),
      ngx_cycle->log);
  if (temp_pool == NULL) {
    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                  "on local: op(add/update) create pool error");
  }

  node = ngx_pcalloc(temp_pool, peer_size);
  if (node == NULL) {
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                  "on local: op(add/update) calloc error");
    return NGX_ERROR;
  }

  node->key = hash;

  peer = (ngx_http_health_detect_peer_t *)&node->color;
  peer->temp_pool = temp_pool;

  peer->default_policy = ngx_http_get_default_detect_policy(policy->data.type);

  peer->policy =
      ngx_pcalloc(peer->temp_pool, sizeof(ngx_health_detect_detect_policy_t));

  peer->policy->data = policy->data;

  rc = ngx_parse_addr_port(peer->temp_pool, &peer->policy->peer_addr,
                           policy->peer_addr.name.data,
                           policy->peer_addr.name.len);
  if (rc == NGX_ERROR || rc == NGX_DECLINED) {
    goto failed;
  }

  peer->policy->peer_name.data =
      ngx_pcalloc(peer->temp_pool, policy->peer_name.len);
  if (peer->policy->peer_name.data == NULL) {
    goto failed;
  }
  ngx_memcpy(peer->policy->peer_name.data, policy->peer_name.data,
             policy->peer_name.len);
  peer->policy->peer_name.len = policy->peer_name.len;

  if (policy->send_content.len != 0) {
    peer->policy->send_content.data =
        ngx_pcalloc(peer->temp_pool, policy->send_content.len);
    if (peer->policy->send_content.data == NULL) {
      goto failed;
    }
    ngx_memcpy(peer->policy->send_content.data, policy->send_content.data,
               policy->send_content.len);
    peer->policy->send_content.len = policy->send_content.len;
  } else {
    ngx_str_null(&peer->policy->send_content);
  }

  ngx_rbtree_insert(&peers_manager_ctx->peers->rbtree, node);

  ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                "on local: op(add/update) add node peer name(%V) peer addr(%V)",
                &policy->peer_name, &policy->peer_addr.name);

  rc = ngx_http_health_detect_add_timers(node);
  if (rc != NGX_OK) {
    goto failed;
  }

  return NGX_OK;

failed:
  if (node) {
    ngx_health_detect_free_node(node);
  }

  ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                "on local: op(add/update) node key(%V) failed",
                &policy->peer_name);

  return NGX_ERROR;
}

static ngx_int_t ngx_health_detect_add_or_update_node(ngx_http_request_t *r,
                                                      void *data) {
  ngx_int_t rc;
  ngx_health_detect_detect_policy_t *policy = data;

  rc = ngx_health_detect_add_or_update_node_on_shm(policy);
  if (rc != NGX_OK) {
    return rc;
  }

  return ngx_health_detect_add_or_update_node_on_local(policy);
}

static void ngx_health_detect_free_node(ngx_rbtree_node_t *node) {
  ngx_http_health_detect_peer_t *peer;

  if (peers_manager_ctx == NULL) {
    return;
  }

  peer = (ngx_http_health_detect_peer_t *)&node->color;

  ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0, "free peer name(%V)",
                &peer->policy->peer_name);

  ngx_http_health_detect_clear_one_peer_all_events(peer);

  ngx_rbtree_delete(&peers_manager_ctx->peers->rbtree, node);

  if (peer->temp_pool != NULL) {
    ngx_destroy_pool(peer->temp_pool);
  }
}

static ngx_int_t ngx_health_detect_delete_node(ngx_http_request_t *r,
                                               void *data) {
  ngx_rbtree_node_t *node_shm, *node;
  ngx_slab_pool_t *shpool;
  uint32_t hash;

  ngx_str_t *key = data;

  if (peers_manager_ctx == NULL) {
    return NGX_ERROR;
  }

  shpool = peers_manager_ctx->peers_shm->shpool;
  hash = ngx_crc32_short(key->data, key->len);

  ngx_shmtx_lock(&shpool->mutex);
  node_shm = ngx_http_health_detect_peers_shm_rbtree_lookup(hash, key);
  if (node_shm != NULL) {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "on shm: op(delete) node key:%V found, delete this node",
                  key);
    ngx_health_detect_shm_free_node(node_shm);
  }

  node = ngx_http_health_detect_peers_rbtree_lookup(hash, key);
  if (node != NULL) {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "on local: op(delete) node key:%V found, delete this node",
                  key);
    ngx_health_detect_free_node(node);
  }

  ngx_shmtx_unlock(&shpool->mutex);

  return NGX_OK;
}

static ngx_int_t ngx_health_detect_delete_all_node(ngx_http_request_t *r,
                                                   void *data) {
  ngx_rbtree_node_t *node_shm, *sentinel;
  ngx_http_health_detect_peers_shm_t *peers_shm;

  if (peers_manager_ctx == NULL) {
    return NGX_ERROR;
  }

  peers_shm = peers_manager_ctx->peers_shm;
  ngx_shmtx_lock(&peers_shm->shpool->mutex);

  node_shm = peers_shm->rbtree.root;
  sentinel = peers_shm->rbtree.sentinel;
  while (node_shm != sentinel) {
    ngx_health_detect_shm_free_node(node_shm);
    node_shm = peers_shm->rbtree.root;
  }
  ngx_shmtx_unlock(&peers_shm->shpool->mutex);

  if (data == NULL || (*(ngx_uint_t *)data == 0)) {
    ngx_http_health_detect_clear_peers_events();
  }

  return NGX_OK;
}

static ngx_http_health_detect_status_format_ctx_t *
get_format_from_request_args(ngx_str_t format_args) {
  ngx_uint_t i;
  for (i = 0; ngx_check_status_formats[i].format.len != 0; i++) {
    if (ngx_strncasecmp(format_args.data,
                        (u_char *)"format=", sizeof("format=") - 1) != 0) {
      return NULL;
    }
    if (((format_args.len - (sizeof("format=") - 1)) ==
         ngx_check_status_formats[i].format.len) &&
        (ngx_strncasecmp(format_args.data + sizeof("format=") - 1,
                         ngx_check_status_formats[i].format.data,
                         ngx_check_status_formats[i].format.len) == 0)) {
      return &ngx_check_status_formats[i];
    }
  }
  return NULL;
}

static ngx_buf_t *
ngx_health_detect_create_temp_response_buf(ngx_http_request_t *r,
                                           ngx_str_t *resp) {
  size_t buffer_size;
  ngx_buf_t *b;

  buffer_size = ngx_pagesize / 4;
  b = ngx_create_temp_buf(r->pool, buffer_size);
  if (b == NULL) {
    return NULL;
  }
  b->last = ngx_snprintf(b->last, b->end - b->last, "%V", resp);

  return b;
}

static ngx_int_t ngx_health_detect_check_all_node_status(ngx_http_request_t *r,
                                                         void *data) {
  ngx_int_t rc;
  size_t buffer_size;
  ngx_buf_t *b;
  ngx_chain_t *out_chain;
  ngx_http_health_detect_status_format_ctx_t *format_ctx;
  ngx_str_t resp;
  ngx_slab_pool_t *shpool;

  shpool = peers_manager_ctx->peers_shm->shpool;

  if (r->args.len == 0) {
    format_ctx = &ngx_check_status_formats[0];
  } else {
    format_ctx = get_format_from_request_args(r->args);
    if (format_ctx == NULL) {
      ngx_str_set(&resp, "status format not valid(json/html)");
      b = ngx_health_detect_create_temp_response_buf(r, &resp);
      goto out;
    }
  }

  buffer_size = ngx_pagesize * 200;
  b = ngx_create_temp_buf(r->pool, buffer_size);

  ngx_shmtx_lock(&shpool->mutex);
  format_ctx->all_node_output(b, peers_manager_ctx->peers_shm);
  ngx_shmtx_unlock(&shpool->mutex);

  r->headers_out.content_type = format_ctx->content_type;

out:
  rc = NGX_HTTP_OK;
  b->last_buf = 1;
  b->last_in_chain = 1;

  out_chain = ngx_alloc_chain_link(r->pool);
  out_chain->buf = b;
  out_chain->next = NULL;

  r->headers_out.status = rc;
  r->headers_out.content_length_n = b->last - b->pos;

  rc = ngx_http_send_header(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return rc;
  }

  return ngx_http_output_filter(r, out_chain);
}

static ngx_int_t ngx_health_detect_check_node_status(ngx_http_request_t *r,
                                                     void *data) {
  ngx_http_health_detect_peer_shm_t *peer_shm;
  ngx_int_t rc;
  size_t len, buffer_size;
  ngx_buf_t *b;
  ngx_chain_t *out_chain;
  ngx_rbtree_node_t *node_shm;
  ngx_http_health_detect_status_format_ctx_t *format_ctx;
  ngx_slab_pool_t *shpool;
  uint32_t hash;
  ngx_str_t resp;

  ngx_str_t *peer_name = data;
  shpool = peers_manager_ctx->peers_shm->shpool;

  if (r->args.len == 0) {
    format_ctx = &ngx_check_status_formats[0];
  } else {
    format_ctx = get_format_from_request_args(r->args);
    if (format_ctx == NULL) {
      ngx_str_set(&resp, "status format not valid(json/html)");
      b = ngx_health_detect_create_temp_response_buf(r, &resp);
      goto out;
    }
  }

  hash = ngx_crc32_short(peer_name->data, peer_name->len);

  ngx_shmtx_lock(&shpool->mutex);

  node_shm = ngx_http_health_detect_peers_shm_rbtree_lookup(hash, peer_name);
  if (node_shm != NULL) {
    peer_shm = (ngx_http_health_detect_peer_shm_t *)&node_shm->color;

    buffer_size = ngx_pagesize;
    b = ngx_create_temp_buf(r->pool, buffer_size);
    format_ctx->one_node_output(b, peer_shm);
    ngx_shmtx_unlock(&shpool->mutex);

    r->headers_out.content_type = format_ctx->content_type;
    goto out;
  }

  ngx_shmtx_unlock(&shpool->mutex);
  ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                "can not find node on server: name:%V", peer_name);

  len = sizeof("can not find node on server: name:") - 1 + peer_name->len;
  resp.data = ngx_pcalloc(r->pool, len);
  if (resp.data == NULL) {
    ngx_str_set(&resp, "can not find node on server");
  } else {
    resp.len = ngx_snprintf(resp.data, len,
                            "can not find node on server: name:%V", peer_name) -
               resp.data;
  }

  b = ngx_health_detect_create_temp_response_buf(r, &resp);

out:
  rc = NGX_HTTP_OK;
  b->last_buf = 1;
  b->last_in_chain = 1;

  out_chain = ngx_alloc_chain_link(r->pool);
  out_chain->buf = b;
  out_chain->next = NULL;

  r->headers_out.status = rc;
  r->headers_out.content_length_n = b->last - b->pos;

  rc = ngx_http_send_header(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return rc;
  }

  return ngx_http_output_filter(r, out_chain);
}

static ngx_int_t ngx_http_health_detect_peek_one_byte(ngx_connection_t *c) {
  char buf[1];
  ngx_int_t n;
  ngx_err_t err;

  n = recv(c->fd, buf, 1, MSG_PEEK);
  err = ngx_socket_errno;

  ngx_log_error(NGX_LOG_DEBUG, c->log, err, "http check  recv(): %i, fd: %d", n,
                c->fd);
  if (n == 1 || (n == -1 && err == NGX_EAGAIN)) {
    return NGX_OK;
  } else {
    return NGX_ERROR;
  }
}

static void ngx_http_health_detect_lru_update_status(
    ngx_http_health_detect_peer_shm_t *peer_shm, ngx_uint_t result) {
  ngx_queue_t *q;

  q = ngx_queue_head(&peer_shm->status.history_status);
  ngx_health_detect_one_peer_status *update_node_status =
      ngx_queue_data(q, ngx_health_detect_one_peer_status, link);
  update_node_status->status = peer_shm->status.latest_status = result;

  ngx_memcpy(update_node_status->access_time.data,
             peer_shm->status.latest_access_time.data,
             peer_shm->status.latest_access_time.len);

  ngx_queue_remove(q);
  ngx_queue_insert_tail(&peer_shm->status.history_status, q);
}

static ngx_int_t ngx_http_health_detect_status_update(ngx_rbtree_node_t *node,
                                                      ngx_uint_t result) {
  ngx_health_detect_one_peer_status *add_status;
  ngx_slab_pool_t *shpool;
  uint32_t hash;
  ngx_rbtree_node_t *node_shm;
  ngx_http_health_detect_peer_t *peer;
  ngx_http_health_detect_peer_shm_t *peer_shm;

  peer = (ngx_http_health_detect_peer_t *)(&node->color);

  ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                "on status update: start update peer name(%V) status(%d)",
                &peer->policy->peer_name, result);

  if (peers_manager_ctx == NULL) {
    return NGX_ERROR;
  }

  shpool = peers_manager_ctx->peers_shm->shpool;

  hash = ngx_crc32_short(peer->policy->peer_name.data,
                         peer->policy->peer_name.len);

  ngx_shmtx_lock(&shpool->mutex);
  node_shm = ngx_http_health_detect_peers_shm_rbtree_lookup(
      hash, &peer->policy->peer_name);
  if (node_shm == NULL) {
    ngx_shmtx_unlock(&shpool->mutex);
    ngx_health_detect_free_node(node);
    ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                  "on status update:peer name(%V) not exit in shm, so needn't "
                  "update status",
                  &peer->policy->peer_name);

    return NGX_DONE;
  }

  peer_shm = (ngx_http_health_detect_peer_shm_t *)&node_shm->color;
  if (peer_shm->policy.data.checksum != peer->policy->data.checksum) {
    ngx_shmtx_unlock(&shpool->mutex);
    ngx_health_detect_free_node(node);

    ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                  "on status update:peer name(%V) exit in shm but policy is "
                  "diff, so needn't update status",
                  &peer->policy->peer_name);

    return NGX_DONE;
  }

  peer_shm->owner = NGX_INVALID_PID;
  peer_shm->access_time = ngx_current_msec;

  ngx_memcpy(peer_shm->status.latest_access_time.data,
             ngx_cached_err_log_time.data, ngx_cached_err_log_time.len);

  if (result == NGX_CHECK_STATUS_UP) {
    peer_shm->rise_count++;
    peer_shm->fall_count = 0;
    if (peer_shm->rise_count < peer_shm->policy.data.rise) {
      goto done;
    }

    peer_shm->rise_count = 0;
  } else {
    peer_shm->rise_count = 0;
    peer_shm->fall_count++;
    if (peer_shm->fall_count < peer_shm->policy.data.fall) {
      goto done;
    }

    peer_shm->fall_count = 0;
  }

  if (peer_shm->status.latest_status != result) {
    peer_shm->status.latest_status = result;

    if (peer_shm->status.current_status_count ==
        peer_shm->status.max_status_count) {

      ngx_http_health_detect_lru_update_status(peer_shm, result);
      ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                    "on status update: lru update peer name(%V) status(%d) "
                    "when status count over limits",
                    &peer->policy->peer_name, result);
      goto done;
    }

    add_status = ngx_slab_calloc_locked(
        shpool, sizeof(ngx_health_detect_one_peer_status));
    if (add_status == NULL) {
      ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "on status update: lru update peer name(%V) status(%d) "
                    "when no enough mem to alloc status",
                    &peer->policy->peer_name, result);
      return NGX_ERROR;
    }

    add_status->access_time.data =
        ngx_slab_calloc_locked(shpool, peer_shm->status.latest_access_time.len);
    if (add_status->access_time.data == NULL) {
      ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "on status update: lru update peer name(%V) status(%d) "
                    "when no enough mem to alloc status",
                    &peer->policy->peer_name, result);
      goto done;
    }

    add_status->access_time.len = peer_shm->status.latest_access_time.len;

    ngx_memcpy(add_status->access_time.data,
               peer_shm->status.latest_access_time.data,
               peer_shm->status.latest_access_time.len);

    add_status->status = peer_shm->status.latest_status;
    ngx_queue_insert_tail(&peer_shm->status.history_status, &add_status->link);
    peer_shm->status.current_status_count++;

    ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                  "on status update: update peer name(%V) status(%d)",
                  &peer->policy->peer_name, result);
  }

done:
  ngx_shmtx_unlock(&shpool->mutex);
  return NGX_OK;
}

static void
ngx_http_health_detect_finish_handler(ngx_http_health_detect_peer_t *peer) {
  if (ngx_http_health_detect_need_exit()) {
    return;
  }
}

static void ngx_http_health_detect_peek_handler(ngx_event_t *event) {
  ngx_connection_t *c;
  ngx_http_health_detect_peer_t *peer;
  ngx_int_t rc;
  ngx_rbtree_node_t *node;

  if (ngx_http_health_detect_need_exit()) {
    return;
  }

  c = event->data;
  node = c->data;
  peer = (ngx_http_health_detect_peer_t *)(&node->color);

  if (ngx_http_health_detect_peek_one_byte(c) == NGX_OK) {
    rc = ngx_http_health_detect_status_update(node, NGX_CHECK_STATUS_UP);
  } else {
    c->error = 1;
    rc = ngx_http_health_detect_status_update(node, NGX_CHECK_STATUS_DOWN);
  }

  ngx_log_error(NGX_LOG_WARN, event->log, 0, "peek handler result(%ui)", rc);

  if (rc != NGX_DONE) {
    ngx_http_health_detect_clean_timeout_event_and_connection(peer);
    ngx_http_health_detect_finish_handler(peer);
  }
}

static void ngx_http_health_detect_timeout_handler(ngx_event_t *event) {
  ngx_http_health_detect_peer_t *peer;
  ngx_rbtree_node_t *node;

  if (ngx_http_health_detect_need_exit()) {
    return;
  }

  node = (ngx_rbtree_node_t *)event->data;
  peer = (ngx_http_health_detect_peer_t *)(&node->color);

  peer->pc.connection->error = 1;

  ngx_log_error(NGX_LOG_WARN, event->log, 0, "check time out with peer: %V ",
                &peer->policy->peer_name);

  if (ngx_http_health_detect_status_update(node, NGX_CHECK_STATUS_DOWN) !=
      NGX_DONE) {
    ngx_http_health_detect_clean_timeout_event_and_connection(peer);
  }
}

static void ngx_http_health_detect_connect_handler(ngx_event_t *event) {
  ngx_int_t rc;
  ngx_connection_t *c;
  ngx_http_health_detect_peer_t *peer;
  ngx_rbtree_node_t *node;

  if (ngx_http_health_detect_need_exit()) {
    return;
  }

  node = (ngx_rbtree_node_t *)event->data;
  peer = (ngx_http_health_detect_peer_t *)(&node->color);

  if (peer->pc.connection != NULL) {
    c = peer->pc.connection;
    ngx_log_error(NGX_LOG_DEBUG, event->log, 0,
                  "on connect handler: last connection still alive when enable "
                  "keep-alive, so send "
                  "data directly");

    if ((rc = ngx_http_health_detect_peek_one_byte(c)) == NGX_OK) {
      goto upstream_check_connect_done;
    } else {
      ngx_close_connection(c);
      peer->pc.connection = NULL;
    }
  }
  ngx_memzero(&peer->pc, sizeof(ngx_peer_connection_t));

  peer->pc.sockaddr = peer->policy->peer_addr.sockaddr;
  peer->pc.socklen = peer->policy->peer_addr.socklen;
  peer->pc.name = &peer->policy->peer_addr.name;
  peer->pc.get = ngx_event_get_peer;
  peer->pc.log = event->log;
  peer->pc.log_error = NGX_ERROR_ERR;
  peer->pc.start_time = ngx_current_msec;

  peer->pc.cached = 0;
  peer->pc.connection = NULL;
  rc = ngx_event_connect_peer(&peer->pc);
  if (rc == NGX_ERROR || rc == NGX_DECLINED) {
    ngx_log_error(NGX_LOG_WARN, event->log, 0,
                  "on connect handler: connect error(%ui)", rc);

    if (ngx_http_health_detect_status_update(node, NGX_CHECK_STATUS_DOWN) !=
        NGX_DONE) {
      ngx_http_health_detect_clean_timeout_event_and_connection(peer);
    }
    return;
  }
  /* NGX_OK or NGX_AGAIN */

  c = peer->pc.connection;
  c->data = node;
  c->log = peer->pc.log;
  c->sendfile = 0;
  c->read->log = c->log;
  c->write->log = c->log;
  c->pool = peer->check_pool;

upstream_check_connect_done:
  peer->state = NGX_HTTP_CHECK_CONNECT_DONE;

  c->write->handler = peer->default_policy->send_handler;
  c->read->handler = peer->default_policy->recv_handler;
  ngx_add_timer(&peer->check_timeout_ev, peer->policy->data.check_timeout);

  if (rc == NGX_OK) {
    c->write->handler(c->write);
  }
}

static void ngx_http_health_detect_start_check_handler(ngx_event_t *event) {
  ngx_msec_int_t interval;
  ngx_http_health_detect_peer_t *peer;
  ngx_slab_pool_t *shpool;
  uint32_t hash;
  ngx_rbtree_node_t *node_shm;
  ngx_http_health_detect_peer_shm_t *peer_shm;
  ngx_rbtree_node_t *node;

  if (ngx_http_health_detect_need_exit()) {
    return;
  }

  node = (ngx_rbtree_node_t *)event->data;
  peer = (ngx_http_health_detect_peer_t *)(&node->color);

  shpool = peers_manager_ctx->peers_shm->shpool;

  hash = ngx_crc32_short(peer->policy->peer_name.data,
                         peer->policy->peer_name.len);
  ngx_shmtx_lock(&shpool->mutex);
  node_shm = ngx_http_health_detect_peers_shm_rbtree_lookup(
      hash, &peer->policy->peer_name);
  if (node_shm == NULL) {
    ngx_shmtx_unlock(&shpool->mutex);
    ngx_health_detect_free_node(node);

    ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                  "on start check handler: peer name(%V) not exit in shm, "
                  "needn't check again",
                  &peer->policy->peer_name);
    return;
  }

  peer_shm = (ngx_http_health_detect_peer_shm_t *)&node_shm->color;
  if (peer_shm->policy.data.checksum != peer->policy->data.checksum) {
    ngx_shmtx_unlock(&shpool->mutex);
    ngx_health_detect_free_node(node);
    return;
  } else {
    ngx_add_timer(event, peer->policy->data.check_interval / 2);

    /* This process is processing this peer now. */
    if (peer_shm->owner == ngx_pid || peer->check_timeout_ev.timer_set) {
      ngx_shmtx_unlock(&shpool->mutex);

      ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                    "on start check handler: current precess(%P) is handing "
                    "peer name(%V)",
                    ngx_pid, &peer->policy->peer_name);
      return;
    }

    /*
     * The current time maybe delayed(some operation take too long)
     * We don't need to trigger the check event at this point.
     */
    if (ngx_current_msec < peer_shm->access_time) {
      ngx_log_error(
          NGX_LOG_WARN, event->log, 0,
          "time maybe delayed, got current_msec:%M, shm_access_time:%M",
          ngx_current_msec, peer_shm->access_time);
      ngx_shmtx_unlock(&shpool->mutex);
      return;
    }

    interval = ngx_current_msec - peer_shm->access_time;

    ngx_log_error(NGX_LOG_WARN, event->log, 0,
                  "http check begin handler owner: %P, "
                  "ngx_pid: %P, interval: %M, check_interval: %M",
                  peer_shm->owner, ngx_pid, interval,
                  peer->policy->data.check_interval);

    if ((interval >= peer->policy->data.check_interval) &&
        (peer_shm->owner == NGX_INVALID_PID)) {

      peer_shm->owner = ngx_pid;

    } else if (interval >= (peer->policy->data.check_interval << 4)) {

      /*
       * If the check peer has been untouched for 2^4 times of
       * the check interval, activate the current timer.
       * Sometimes, the checking process may disappear
       * under some abnormal circumstances, and the clean event
       * will never be triggered.
       */
      peer_shm->owner = ngx_pid;
      peer_shm->access_time = ngx_current_msec;
    }

    if (peer_shm->owner == ngx_pid) {
      ngx_shmtx_unlock(&shpool->mutex);
      ngx_log_error(
          NGX_LOG_WARN, event->log, 0,
          "on start check handler: start check peer name addr:%V type:%ui",
          &peer->policy->peer_name, peer->policy->data.type);
      ngx_http_health_detect_connect_handler(event);
      return;
    }
    ngx_shmtx_unlock(&shpool->mutex);
  }
}

static ngx_int_t ngx_http_health_detect_add_timers(ngx_rbtree_node_t *node) {
  ngx_msec_int_t delay;
  ngx_http_health_detect_peer_t *peer;

  peer = (ngx_http_health_detect_peer_t *)(&node->color);

  peer->check_ev.handler = ngx_http_health_detect_start_check_handler;
  peer->check_ev.log = ngx_cycle->log;
  peer->check_ev.data = node;
  peer->check_ev.timer_set = 0;

  peer->check_timeout_ev.handler = ngx_http_health_detect_timeout_handler;
  peer->check_timeout_ev.log = ngx_cycle->log;
  peer->check_timeout_ev.data = node;
  peer->check_timeout_ev.timer_set = 0;

  if (peer->default_policy->need_pool) {
    peer->check_pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (peer->check_pool == NULL) {
      return NGX_ERROR;
    }
  }

  srandom(ngx_pid);
  delay = peer->policy->data.check_interval > 1000
              ? peer->policy->data.check_interval
              : 1000;
  ngx_add_timer(&peer->check_ev, ngx_random() % delay);

  ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0, "add timer for peer name(%V)",
                &peer->policy->peer_name);
  return NGX_OK;
}

static ngx_int_t ngx_parse_addr_on_slab_pool_locked(ngx_slab_pool_t *pool,
                                                    ngx_addr_t *addr,
                                                    u_char *text, size_t len) {
  in_addr_t inaddr;
  ngx_uint_t family;
  struct sockaddr_in *sin;
#if (NGX_HAVE_INET6)
  struct in6_addr inaddr6;
  struct sockaddr_in6 *sin6;

  /*
   * prevent MSVC8 warning:
   *    potentially uninitialized local variable 'inaddr6' used
   */
  ngx_memzero(&inaddr6, sizeof(struct in6_addr));
#endif

  inaddr = ngx_inet_addr(text, len);

  if (inaddr != INADDR_NONE) {
    family = AF_INET;
    len = sizeof(struct sockaddr_in);

#if (NGX_HAVE_INET6)
  } else if (ngx_inet6_addr(text, len, inaddr6.s6_addr) == NGX_OK) {
    family = AF_INET6;
    len = sizeof(struct sockaddr_in6);

#endif
  } else {
    return NGX_DECLINED;
  }

  addr->sockaddr = ngx_slab_calloc_locked(pool, len);
  if (addr->sockaddr == NULL) {
    return NGX_ERROR;
  }

  addr->sockaddr->sa_family = (u_char)family;
  addr->socklen = len;
  switch (family) {

#if (NGX_HAVE_INET6)
  case AF_INET6:
    sin6 = (struct sockaddr_in6 *)addr->sockaddr;
    ngx_memcpy(sin6->sin6_addr.s6_addr, inaddr6.s6_addr, 16);
    break;
#endif

  default: /* AF_INET */
    sin = (struct sockaddr_in *)addr->sockaddr;
    sin->sin_addr.s_addr = inaddr;
    break;
  }

  return NGX_OK;
}

static ngx_int_t ngx_parse_addr_port_on_slab_pool_locked(ngx_slab_pool_t *pool,
                                                         ngx_addr_t *addr,
                                                         u_char *text,
                                                         size_t len) {
  u_char *p, *last;
  size_t plen;
  ngx_int_t rc, port;

  rc = ngx_parse_addr_on_slab_pool_locked(pool, addr, text, len);

  if (rc != NGX_DECLINED) {
    return rc;
  }

  last = text + len;

#if (NGX_HAVE_INET6)
  if (len && text[0] == '[') {

    p = ngx_strlchr(text, last, ']');

    if (p == NULL || p == last - 1 || *++p != ':') {
      return NGX_DECLINED;
    }

    text++;
    len -= 2;

  } else
#endif

  {
    p = ngx_strlchr(text, last, ':');

    if (p == NULL) {
      return NGX_DECLINED;
    }
  }

  p++;
  plen = last - p;

  port = ngx_atoi(p, plen);

  if (port < 1 || port > 65535) {
    return NGX_DECLINED;
  }

  len -= plen + 1;

  rc = ngx_parse_addr_on_slab_pool_locked(pool, addr, text, len);

  if (rc != NGX_OK) {
    return rc;
  }

  ngx_inet_set_port(addr->sockaddr, (in_port_t)port);

  switch (addr->sockaddr->sa_family) {
  case AF_INET:
    len = NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1;
    break;
#if (NGX_HAVE_INET6)
  case AF_INET6:
    len = NGX_INET6_ADDRSTRLEN + sizeof(":65535") - 1;
    break;
#endif
  default:
    return NGX_ERROR;
  }

  p = ngx_slab_calloc_locked(pool, len);
  if (p == NULL) {
    return NGX_ERROR;
  }

#if (nginx_version >= 1005012)
  len = ngx_sock_ntop(addr->sockaddr, addr->socklen, p, len, 1);
#else
  len = ngx_sock_ntop(dst->sockaddr, p, len, 1);
#endif

  addr->name.len = len;
  addr->name.data = p;

  return NGX_OK;
}

static ngx_health_detect_default_detect_policy_t *
ngx_http_get_default_detect_policy(ngx_uint_t type) {
  ngx_uint_t i;

  for (i = 0; /* void */; i++) {

    if (ngx_health_detect_default_detect_policy[i].type == 0) {
      break;
    }

    if (type != ngx_health_detect_default_detect_policy[i].type) {
      continue;
    }

    return &ngx_health_detect_default_detect_policy[i];
  }

  return NULL;
}

static ngx_int_t
ngx_http_health_detect_process_request_with_empty_body(ngx_http_request_t *r) {
  ngx_int_t rc;
  ngx_uint_t i;
  size_t len;
  ngx_buf_t *b;
  ngx_chain_t *out;
  ngx_str_t peer_name;

  rc = ngx_http_discard_request_body(r);
  if (rc == NGX_ERROR) {
    goto out;
  }

  for (i = 0; api_route[i].op_code != 0; i++) {
    if (api_route[i].op_des.len > r->uri.len) {
      continue;
    }

    if (r->uri.len == api_route[i].op_des.len) {
      if (ngx_strncasecmp(api_route[i].op_des.data, r->uri.data,
                          api_route[i].op_des.len) == 0) {
        if (api_route[i].op_code == CHECK_ALL_PEER_STATUS_OP) {
          return api_route[i].op_handler(r, NULL);
        }

        if (api_route[i].op_code == DELETE_ALL_PEERS) {
          rc = api_route[i].op_handler(r, NULL);
          rc = (rc == NGX_ERROR) ? NGX_HTTP_INTERNAL_SERVER_ERROR : NGX_HTTP_OK;
          goto out;
        }
      }
    } else {
      if (ngx_strncasecmp(api_route[i].op_des.data, r->uri.data,
                          api_route[i].op_des.len) == 0) {
        break;
      }
    }
  }

  if (api_route[i].op_code == 0) {
    rc = NGX_HTTP_BAD_REQUEST;
    goto out;
  }

  peer_name.data = r->uri.data + api_route[i].op_des.len;
  peer_name.len = r->uri.len - api_route[i].op_des.len;

  if (peer_name.len > PEER_NAME_LEN_MAX_VALUE) {
    rc = NGX_HTTP_REQUEST_URI_TOO_LARGE;
    goto out;
  }

  if (api_route[i].op_code == CHECK_ONE_PEER_STATUS) {
    return api_route[i].op_handler(r, &peer_name);
  }

  rc = api_route[i].op_handler(r, &peer_name);
  rc = (rc == NGX_ERROR) ? NGX_HTTP_INTERNAL_SERVER_ERROR : NGX_HTTP_OK;

out:
  len = r->uri.len;
  if (r->args.len) {
    len += r->args.len + 1;
  }

  b = ngx_create_temp_buf(r->pool, len);
  b->last = ngx_cpymem(b->pos, r->uri.data, r->uri.len);
  if (r->args.len) {
    b->last = ngx_cpymem(b->last, r->args.data, r->args.len);
    *(b->last++) = ' ';
  }

  r->headers_out.status = rc;
  r->headers_out.content_length_n = len;

  rc = ngx_http_send_header(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return rc;
  }

  b->last_buf = 1;
  b->last_in_chain = 1;

  out = ngx_alloc_chain_link(r->pool);
  out->buf = b;
  out->next = NULL;

  return ngx_http_output_filter(r, out);
}

static ngx_int_t
ngx_health_detect_check_fall_rise_is_valid(ngx_msec_int_t check_interval) {
  if (check_interval < PEER_CHECK_FALL_RISE_MIN_VALUE ||
      check_interval > PEER_CHECK_FALL_RISE_MAX_VALUE) {
    return 0;
  }
  return 1;
}

static ngx_int_t
ngx_health_detect_check_interval_is_valid(ngx_msec_int_t check_interval) {
  if (check_interval < PEER_CHECK_INTERVAL_MIN_VALUE ||
      check_interval > PEER_CHECK_INTERVAL_MAX_VALUE) {
    return 0;
  }
  return 1;
}

static ngx_int_t
ngx_health_detect_check_timeout_is_valid(ngx_msec_int_t check_interval) {
  if (check_interval < PEER_CHECK_TIMEOUT_MIN_VALUE ||
      check_interval > PEER_CHECK_TIMEOUT_MAX_VALUE) {
    return 0;
  }
  return 1;
}

static ngx_int_t
ngx_health_detect_check_keepalive_time_is_valid(ngx_msec_int_t keepalive_time) {
  if (keepalive_time < PEER_CHECK_KEEPALIVE_TIME_MIN_VALUE ||
      keepalive_time > PEER_CHECK_KEEPALIVE_TIME_MAX_VALUE) {
    return 0;
  }
  return 1;
}

static ngx_health_detect_detect_policy_t *
ngx_health_detect_prase_request_body(ngx_http_request_t *r, ngx_str_t peer_name,
                                     ngx_int_t *prase_error) {
  ngx_uint_t request_body_len;
  ngx_chain_t *cl;
  ngx_uint_t i, len, mask;
  ngx_str_t str;
  ngx_buf_t *buf;
  cJSON *requst_body_json;
  ngx_health_detect_default_detect_policy_t *default_policy;
  ngx_health_detect_detect_policy_t *policy;
  cJSON *attr;
  char *data;
  ngx_http_health_detect_srv_conf_t *hdscf;

  hdscf = ngx_http_get_module_srv_conf(r, ngx_http_health_detect_module);
  if (hdscf == NULL) {
    return NULL;
  }

  mask = 0;
  request_body_len = 0;

  for (cl = r->request_body->bufs; cl; cl = cl->next) {
    request_body_len += (cl->buf->last - cl->buf->pos);
  }

  if (request_body_len == 0) {
    *prase_error = NGX_PRASE_REQ_ERR;
    return NULL;
  }

  buf = ngx_create_temp_buf(r->pool, request_body_len);
  if (buf == NULL) {
    *prase_error = NGX_PRASE_REQ_ERR;
    return NULL;
  }

  for (cl = r->request_body->bufs; cl; cl = cl->next) {
    buf->last =
        ngx_cpymem(buf->last, cl->buf->pos, cl->buf->last - cl->buf->pos);
  }

  requst_body_json = cJSON_Parse((char *)buf->pos);
  if (requst_body_json == NULL) {
    *prase_error = NGX_PRASE_REQ_ERR;
    return NULL;
  } else {
    /*
     * attrs :
     * must:
     * type  ngx_str_t
     * peer_name  ngx_str_t
     * peer_addr  ngx_str_t
     *
     * option:
     * send_content  ngx_str_t  empty means use default value
     * alert_method  ngx_str_t  empty means use default value
     * expect_response_status  ngx_str_t  empty means use default value
     * check_interval  ngx_msec_int_t  empty means use default value
     * check_timeout  ngx_msec_int_t  empty means use default value
     * rise  ngx_uint_t  empty means use default value
     * fall  ngx_uint_t  empty means use default value
     * need_keepalive  ngx_uint_t  empty means use default value
     * keepalive_time  ngx_msec_int_t  empty means use default value
     * */
    policy = ngx_pcalloc(r->pool, sizeof(ngx_health_detect_detect_policy_t));

    policy->data.checksum = ngx_murmur_hash2(buf->pos, request_body_len);

    policy->peer_name.data = ngx_pstrdup(r->pool, &peer_name);
    if (policy->peer_name.data == NULL) {
      *prase_error = NGX_PRASE_REQ_ERR;
      goto fail;
    }
    policy->peer_name.len = peer_name.len;

    ngx_memcpy(policy->peer_name.data, peer_name.data, peer_name.len);

    attr = cJSON_GetObjectItem(requst_body_json, "peer_type");
    if (attr == NULL) {
      *prase_error = NGX_PRASE_REQ_PEER_TYPE_NOT_FOUND;
      goto fail;
    } else {
      data = attr->valuestring;
      len = ngx_strlen(data);
      str.data = ngx_pcalloc(r->pool, len);
      if (str.data == NULL) {
        *prase_error = NGX_PRASE_REQ_ERR;
        goto fail;
      }
      str.len = len;
      ngx_memcpy(str.data, data, len);

      policy->data.type = ngx_health_detect_get_policy_type_from_string(&str);
      if (!policy->data.type) {
        *prase_error = NGX_PRASE_REQ_INVALID_PEER_TYPE;
        goto fail;
      }
    }

    default_policy = ngx_http_get_default_detect_policy(policy->data.type);

    attr = cJSON_GetObjectItem(requst_body_json, (char *)"peer_addr");
    if (attr == NULL) {
      *prase_error = NGX_PRASE_REQ_PEER_ADDR_NOT_FOUND;
      goto fail;
    } else {
      data = attr->valuestring;
      len = ngx_strlen(data);
      *prase_error =
          ngx_parse_addr_port(r->pool, &policy->peer_addr, (u_char *)data, len);
      if (*prase_error == NGX_ERROR || *prase_error == NGX_DECLINED) {
        *prase_error = NGX_PRASE_REQ_INVALID_PEER_ADDR;
        goto fail;
      }
      in_port_t port = ngx_inet_get_port(policy->peer_addr.sockaddr);
      if (port == 0) {
        *prase_error = NGX_PRASE_REQ_INVALID_PEER_ADDR;
        goto fail;
      }
      policy->peer_addr.name.data = ngx_pcalloc(r->pool, len);
      if (policy->peer_addr.name.data == NULL) {
        *prase_error = NGX_PRASE_REQ_ERR;
        goto fail;
      }
      policy->peer_addr.name.len = len;
      ngx_memcpy(policy->peer_addr.name.data, data, len);
    }

    attr = cJSON_GetObjectItem(requst_body_json, (char *)"send_content");
    if (attr == NULL) {
      ngx_str_null(&policy->send_content);
    } else {
      data = attr->valuestring;
      len = ngx_strlen(data);
      if (len > MAX_SEND_CONTENT_LEN_MAX_VALUE) {
        *prase_error = NGX_PRASE_REQ_SEND_CONTENT_TOO_LONG;
        goto fail;
      }
      policy->send_content.data = ngx_pcalloc(r->pool, len);
      if (policy->send_content.data == NULL) {
        *prase_error = NGX_PRASE_REQ_ERR;
        goto fail;
      }
      policy->send_content.len = len;
      ngx_memcpy(policy->send_content.data, data, len);
    }

    attr = cJSON_GetObjectItem(requst_body_json, (char *)"alert_method");
    if (attr == NULL) {
      policy->data.alert_method =
          ngx_health_detect_get_policy_alert_method_from_string(
              &default_policy->alert_method);
    } else {
      data = attr->valuestring;
      len = ngx_strlen(data);
      str.data = ngx_pcalloc(r->pool, len);
      if (str.data == NULL) {
        *prase_error = NGX_PRASE_REQ_ERR;
        goto fail;
      }
      str.len = len;
      ngx_memcpy(str.data, data, len);

      policy->data.alert_method =
          ngx_health_detect_get_policy_alert_method_from_string(&str);
      if (!policy->data.alert_method) {
        *prase_error = NGX_PRASE_REQ_INVALID_ALERT_METHOD;
        goto fail;
      }
    }

    attr =
        cJSON_GetObjectItem(requst_body_json, (char *)"expect_response_status");
    if (attr == NULL) {
      policy->data.expect_response_status.http_status =
          default_policy->expect_response_status;
    } else {
      data = attr->valuestring;

      for (i = 0; ngx_check_http_expect_alive_masks[i].name.len != 0; i++) {
        if (ngx_strcasestrn(
                (u_char *)data,
                (char *)ngx_check_http_expect_alive_masks[i].name.data,
                ngx_check_http_expect_alive_masks[i].name.len - 1) != NULL) {
          mask |= ngx_check_http_expect_alive_masks[i].mask;
        }
      }
      if (mask == 0) {
        *prase_error = NGX_PRASE_REQ_INVALID_EXPECT_RESPONSE_STATUS;
      }

      policy->data.expect_response_status.http_status = mask;
    }

    attr = cJSON_GetObjectItem(requst_body_json, "fall");
    if (attr == NULL) {
      policy->data.fall = default_policy->fall;
    } else {
      policy->data.fall = attr->valueint;
      if (!ngx_health_detect_check_fall_rise_is_valid(policy->data.fall)) {
        *prase_error = NGX_PRASE_REQ_INVALID_CHECK_FALL_RISE_NUMBER;
        goto fail;
      }
    }

    attr = cJSON_GetObjectItem(requst_body_json, "rise");
    if (attr == NULL) {
      policy->data.rise = default_policy->rise;
    } else {
      policy->data.rise = attr->valueint;
      if (!ngx_health_detect_check_fall_rise_is_valid(policy->data.rise)) {
        *prase_error = NGX_PRASE_REQ_INVALID_CHECK_FALL_RISE_NUMBER;
        goto fail;
      }
    }

    attr = cJSON_GetObjectItem(requst_body_json, "check_interval");
    if (attr == NULL) {
      policy->data.check_interval = default_policy->check_interval;
    } else {
      policy->data.check_interval = attr->valueint;
      if (!ngx_health_detect_check_interval_is_valid(
              policy->data.check_interval)) {
        *prase_error = NGX_PRASE_REQ_INVALID_CHECK_INTERVAL;
        goto fail;
      }
    }

    attr = cJSON_GetObjectItem(requst_body_json, "check_timeout");
    if (attr == NULL) {
      policy->data.check_timeout = default_policy->check_timeout;
    } else {
      policy->data.check_timeout = attr->valueint;
      if (!ngx_health_detect_check_timeout_is_valid(
              policy->data.check_timeout)) {
        *prase_error = NGX_PRASE_REQ_INVALID_CHECK_TIMEOUT;
        goto fail;
      }
    }

    attr = cJSON_GetObjectItem(requst_body_json, "need_keepalive");
    if (attr == NULL) {
      policy->data.need_keepalive = default_policy->need_keepalive;
    } else {
      policy->data.need_keepalive = attr->valueint;
      if (policy->data.need_keepalive != 0 &&
          policy->data.need_keepalive != 1) {
        *prase_error = NGX_PRASE_REQ_NEED_KEEPALIVE_NOT_BOOL;
        goto fail;
      }
    }

    attr = cJSON_GetObjectItem(requst_body_json, "keepalive_time");
    if (attr == NULL) {
      policy->data.keepalive_time = default_policy->keepalive_time;
    } else {
      policy->data.keepalive_time = attr->valueint;
      if (!ngx_health_detect_check_keepalive_time_is_valid(
              policy->data.keepalive_time)) {
        *prase_error = NGX_PRASE_REQ_INVALID_KEEPALIVE_TIME;
        goto fail;
      }
    }

    *prase_error = NGX_PRASE_REQ_OK;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "policy:peer_name(%V) type(%ui) peer_addr(%V)"
                  "send_content(%V) alert_method(%ui) "
                  "expect_response_status(%ui) "
                  "check_interval(%ui) check_timeout(%ui) fall(%ui) rise(%ui)",
                  &policy->peer_name, policy->data.type,
                  &policy->peer_addr.name,
                  policy->send_content.len == 0
                      ? &ngx_http_get_default_detect_policy(policy->data.type)
                             ->default_send_content
                      : &policy->send_content,
                  policy->data.alert_method,
                  policy->data.expect_response_status.http_status,
                  policy->data.check_interval, policy->data.check_timeout,
                  policy->data.fall, policy->data.rise);
  }

  cJSON_Delete(requst_body_json);
  return policy;

fail:
  if (requst_body_json != NULL) {
    cJSON_Delete(requst_body_json);
  }
  return NULL;
}

static void
ngx_http_health_detect_process_request_with_body(ngx_http_request_t *r) {
  ngx_uint_t i;
  ngx_health_detect_detect_policy_t *policy;
  size_t len;
  ngx_buf_t *b;
  ngx_chain_t *out;
  ngx_str_t peer_name;
  ngx_int_t rc, prase_error;
  ngx_str_t resp;
  u_char *data;

  for (i = 0; api_route[i].op_code != 0; i++) {
    if (api_route[i].op_des.len >= r->uri.len) {
      continue;
    }
    if (ngx_strncasecmp(api_route[i].op_des.data, r->uri.data,
                        api_route[i].op_des.len) == 0) {
      break;
    }
  }

  if (api_route[i].op_code == 0) {
    ngx_str_set(&resp, "NGX_PRASE_REQ_OPERATOT_INVALID");
    rc = NGX_HTTP_BAD_REQUEST;
    goto out;
  }

  peer_name.data = r->uri.data + api_route[i].op_des.len;
  peer_name.len = r->uri.len - api_route[i].op_des.len;

  if (peer_name.len > PEER_NAME_LEN_MAX_VALUE) {
    ngx_str_set(&resp, "NGX_PRASE_REQ_PEER_NAME_TOO_LONG");
    rc = NGX_HTTP_BAD_REQUEST;
    goto out;
  }

  ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                "recv method: %d req uri:%V req args:%V peer name:%V ",
                r->method, &r->uri, &r->args, &peer_name);

  policy = ngx_health_detect_prase_request_body(r, peer_name, &prase_error);
  if (policy == NULL) {
    switch (prase_error) {
    case NGX_PRASE_REQ_PEER_NAME_TOO_LONG:
      ngx_str_set(&resp, "NGX_PRASE_REQ_PEER_NAME_TOO_LONG");
      break;
    case NGX_PRASE_REQ_PEER_TYPE_NOT_FOUND:
      ngx_str_set(&resp, "NGX_PRASE_REQ_PEER_TYPE_NOT_FOUND");
      break;
    case NGX_PRASE_REQ_INVALID_PEER_TYPE:
      ngx_str_set(&resp, "NGX_PRASE_REQ_INVALID_PEER_TYPE");
      break;
    case NGX_PRASE_REQ_PEER_ADDR_NOT_FOUND:
      ngx_str_set(&resp, "NGX_PRASE_REQ_PEER_ADDR_NOT_FOUND");
      break;
    case NGX_PRASE_REQ_INVALID_PEER_ADDR:
      ngx_str_set(&resp, "NGX_PRASE_REQ_INVALID_PEER_ADDR");
      break;
    case NGX_PRASE_REQ_SEND_CONTENT_TOO_LONG:
      ngx_str_set(&resp, "NGX_PRASE_REQ_SEND_CONTENT_TOO_LONG");
      break;
    case NGX_PRASE_REQ_INVALID_ALERT_METHOD:
      ngx_str_set(&resp, "NGX_PRASE_REQ_INVALID_ALERT_METHOD");
      break;
    case NGX_PRASE_REQ_INVALID_EXPECT_RESPONSE_STATUS:
      ngx_str_set(&resp, "NGX_PRASE_REQ_INVALID_EXPECT_RESPONSE_STATUS");
      break;
    case NGX_PRASE_REQ_INVALID_CHECK_INTERVAL:
      ngx_str_set(&resp, "NGX_PRASE_REQ_INVALID_CHECK_INTERVAL");
      break;
    case NGX_PRASE_REQ_INVALID_CHECK_TIMEOUT:
      ngx_str_set(&resp, "NGX_PRASE_REQ_INVALID_CHECK_TIMEOUT");
      break;
    case NGX_PRASE_REQ_INVALID_CHECK_FALL_RISE_NUMBER:
      ngx_str_set(&resp, "NGX_PRASE_REQ_INVALID_CHECK_FALL_RISE_NUMBER");
      break;
    case NGX_PRASE_REQ_NEED_KEEPALIVE_NOT_BOOL:
      ngx_str_set(&resp, "NGX_PRASE_REQ_NEED_KEEPALIVE_NOT_BOOL");
      break;
    case NGX_PRASE_REQ_INVALID_KEEPALIVE_TIME:
      ngx_str_set(&resp, "NGX_PRASE_REQ_INVALID_KEEPALIVE_TIME");
      break;

    default:
      ngx_str_set(&resp, "NGX_PRASE_REQ_ERR");
    }

    rc = NGX_HTTP_BAD_REQUEST;
    goto out;
  }

  rc = api_route[i].op_handler(r, policy);
  if (rc == NGX_ERROR) {
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                  "op_handler invoke error");
    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
  } else {
    rc = NGX_HTTP_OK;
  }

  len = r->uri.len;
  if (r->args.len) {
    len += r->args.len + 1;
  }

  data = ngx_pcalloc(r->pool, len);

  if (r->args.len) {
    data = ngx_cpymem(ngx_cpymem(data, r->uri.data, r->uri.len), r->args.data,
                      r->args.len);
    *(data++) = ' ';
  } else {
    ngx_memcpy(data, r->uri.data, r->uri.len);
  }

  resp.len = len;
  resp.data = data;

out:
  b = ngx_health_detect_create_temp_response_buf(r, &resp);

  r->headers_out.status = rc;
  r->headers_out.content_length_n = b->last - b->pos;

  rc = ngx_http_send_header(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    ngx_http_finalize_request(r, rc);
    return;
  }

  b->last_buf = 1;
  b->last_in_chain = 1;

  out = ngx_alloc_chain_link(r->pool);
  out->buf = b;
  out->next = NULL;

  ngx_http_finalize_request(r, ngx_http_output_filter(r, out));
}

static ngx_int_t ngx_http_health_detect_handler(ngx_http_request_t *r) {
  ngx_int_t rc;

  if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_POST | NGX_HTTP_DELETE))) {
    return NGX_DECLINED;
  }

  if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_DELETE) {
    return ngx_http_health_detect_process_request_with_empty_body(r);
  }

  rc = ngx_http_read_client_request_body(
      r, ngx_http_health_detect_process_request_with_body);
  if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
    return rc;
  }

  return NGX_DONE;
}

static ngx_int_t ngx_http_health_detect_init(ngx_conf_t *cf) {
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;

  if (peers_manager_ctx == NULL || peers_manager_ctx->hdscf->enable == 0) {
    return NGX_OK;
  }

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }
  *h = ngx_http_health_detect_handler;

  return NGX_OK;
}

static void
ngx_http_health_detect_reload_peer_node(ngx_rbtree_node_t *node_shm,
                                        ngx_rbtree_node_t *sentinel) {
  ngx_http_health_detect_peer_shm_t *peer_shm;
  uint32_t hash;
  ngx_str_t *peer_name;
  ngx_rbtree_node_t *node;

  if (node_shm == sentinel) {
    return;
  }

  ngx_http_health_detect_reload_peer_node(node_shm->left, sentinel);

  peer_shm = (ngx_http_health_detect_peer_shm_t *)(&node_shm->color);

  peer_name = &peer_shm->policy.peer_name;

  hash = ngx_crc32_short(peer_name->data, peer_name->len);
  node = ngx_http_health_detect_peers_rbtree_lookup(hash, peer_name);
  if (node == NULL) {
    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                  "on reload peer: reload peer name(%V) on perocess(%P)",
                  peer_name, ngx_pid);
    ngx_health_detect_add_or_update_node_on_local(&peer_shm->policy);
  }

  ngx_http_health_detect_reload_peer_node(node_shm->right, sentinel);
}

static void
ngx_http_health_detect_add_reload_timers_handler(ngx_event_t *event) {
  ngx_rbtree_node_t *node_shm;
  ngx_rbtree_node_t *sentinel;
  ngx_slab_pool_t *shpool;
  ngx_http_health_detect_peers_shm_t *peers_shm;

  if (ngx_http_health_detect_need_exit()) {
    return;
  }

  peers_shm = peers_manager_ctx->peers_shm;
  shpool = peers_shm->shpool;

  node_shm = peers_shm->rbtree.root;
  sentinel = peers_shm->rbtree.sentinel;

  ngx_shmtx_lock(&shpool->mutex);
  ngx_http_health_detect_reload_peer_node(node_shm, sentinel);
  ngx_shmtx_unlock(&shpool->mutex);

  ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                "reload with start flag(%ui) on %P", 0, ngx_pid);

  ngx_add_timer(event, 3000);
}

static ngx_int_t ngx_http_health_detect_add_reload_timers(ngx_cycle_t *cycle) {
  ngx_msec_int_t delay;
  ngx_event_t *reload_timer_ev;

  reload_timer_ev = &peers_manager_ctx->reload_timer_ev;
  reload_timer_ev->handler = ngx_http_health_detect_add_reload_timers_handler;
  reload_timer_ev->log = cycle->log;
  reload_timer_ev->data = NULL;
  reload_timer_ev->timer_set = 0;

  delay = ngx_random() % 1000;
  ngx_add_timer(reload_timer_ev, delay);

  ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0, "add reload timer");
  return NGX_OK;
}

static ngx_int_t ngx_http_health_detect_init_process(ngx_cycle_t *cycle) {
  ngx_http_health_detect_peers_t *peers;

  if (ngx_process != NGX_PROCESS_WORKER) {
    return NGX_OK;
  }

  if (peers_manager_ctx == NULL) {
    return NGX_OK;
  }

  peers = ngx_pcalloc(cycle->pool, sizeof(ngx_http_health_detect_peers_t));
  if (peers == NULL) {
    ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "malloc local peers error");
    return NGX_ERROR;
  }

  ngx_rbtree_init(&peers->rbtree, &peers->sentinel,
                  ngx_http_health_detect_peer_rbtree_insert_value);

  peers_manager_ctx->peers = peers;

  return ngx_http_health_detect_add_reload_timers(cycle);
}