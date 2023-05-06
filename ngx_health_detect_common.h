#ifndef NGX_HEALTH_DETECT_MODULE_COMMON_H_
#define NGX_HEALTH_DETECT_MODULE_COMMON_H_

#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_ALERT_METHOD_LOG 0x0001
#define NGX_HTTP_ALERT_METHOD_SYSLOG 0x0002

#define PEER_NAME_LEN_MAX_VALUE 200

#define PEER_CHECK_FALL_RISE_MIN_VALUE 1
#define PEER_CHECK_FALL_RISE_MAX_VALUE 10

#define PEER_CHECK_INTERVAL_MIN_VALUE 100
#define PEER_CHECK_INTERVAL_MAX_VALUE 60 * 1000

#define PEER_CHECK_TIMEOUT_MIN_VALUE 500
#define PEER_CHECK_TIMEOUT_MAX_VALUE 60 * 5 * 1000

#define PEER_CHECK_KEEPALIVE_TIME_MIN_VALUE 10 * 1000
#define PEER_CHECK_KEEPALIVE_TIME_MAX_VALUE 24 * 3600 * 1000

#define DEFAULT_CHECK_SHM_SIZE 10 * 1024 * 1024
#define DEFAULT_PEER_NUMS_MAX_VALUE 6000

#define MAX_SEND_CONTENT_LEN_MAX_VALUE 300

#define MAX_STATUS_CHANGE_COUNT_DEFAULT_VALUE 5
#define MAX_STATUS_CHANGE_COUNT_MAX_VALUE 50

#define NGX_HTTP_CHECK_TCP 0x0001
#define NGX_HTTP_CHECK_HTTP 0x0002
#define NGX_HTTP_CHECK_SSL_HELLO 0x0004

#define NGX_CHECK_STATUS_DOWN 0x0001
#define NGX_CHECK_STATUS_UP 0x0002
#define NGX_CHECK_STATUS_INVALID 0x0003

#define NGX_CHECK_HTTP_2XX 0x0002
#define NGX_CHECK_HTTP_3XX 0x0004
#define NGX_CHECK_HTTP_4XX 0x0008
#define NGX_CHECK_HTTP_5XX 0x0010
#define NGX_CHECK_HTTP_ERR 0x8000

typedef struct ngx_health_detect_default_detect_policy_s
    ngx_health_detect_default_detect_policy_t;

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

typedef struct {
    ngx_uint_t type;
    ngx_uint_t alert_method;
    union {
        ngx_uint_t return_code;
        ngx_uint_t http_status;
    } expect_response_status;

    ngx_uint_t default_down;

    ngx_uint_t fall;
    ngx_uint_t rise;

    ngx_msec_t check_interval;
    ngx_msec_t check_timeout;

    ngx_uint_t need_keepalive;
    ngx_msec_t keepalive_time;
} ngx_health_detect_policy_data_t;

typedef struct {
    ngx_str_t peer_name;
    ngx_addr_t peer_addr;
    ngx_str_t send_content;

    ngx_health_detect_policy_data_t data;

    ngx_uint_t checksum;
} ngx_health_detect_detect_policy_t;

typedef struct {
    u_char color;

    ngx_shmtx_sh_t lock;
    ngx_pid_t owner;

    ngx_health_detect_detect_policy_t policy;
    ngx_health_detect_peer_status_t status;

    ngx_msec_t access_time;
    ngx_uint_t fall_count;
    ngx_uint_t rise_count;
} ngx_health_detect_peer_shm_t;

typedef struct {
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
} ngx_health_detect_peer_t;

typedef struct {
    ngx_uint_t number;
    ngx_uint_t max_number;
    ngx_uint_t checksum;

    ngx_rbtree_t rbtree; /* ngx_http_health_detect_peer_shm_t */
    ngx_rbtree_node_t sentinel;

    ngx_slab_pool_t *shpool;
} ngx_health_detect_peers_shm_t;

typedef struct {
    ngx_rbtree_t rbtree; /* ngx_health_detect_peer_t */
    ngx_rbtree_node_t sentinel;

    ngx_uint_t checksum;
} ngx_health_detect_peers_t;

typedef struct {
    ngx_event_t reload_timer_ev;

    ngx_health_detect_peers_t *peers;
    ngx_health_detect_peers_shm_t *peers_shm;

    void *hdmcf;
} ngx_health_detect_peers_manager_t;

typedef ngx_int_t (*ngx_health_detect_packet_init_pt)(
    ngx_health_detect_peer_t *peer);
typedef ngx_int_t (*ngx_health_detect_packet_parse_pt)(
    ngx_health_detect_peer_t *peer);
typedef void (*ngx_health_detect_packet_clean_pt)(
    ngx_health_detect_peer_t *peer);

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
    ngx_health_detect_packet_init_pt init;
    ngx_health_detect_packet_parse_pt parse;
    ngx_health_detect_packet_clean_pt reinit;

    unsigned need_pool;

    ngx_uint_t need_keepalive;
    ngx_msec_t keepalive_time;

    ngx_msec_t check_interval;
    ngx_msec_t check_timeout;
};

ngx_int_t ngx_health_detect_check_fall_rise_is_valid(ngx_msec_int_t count);

ngx_int_t ngx_health_detect_check_interval_is_valid(
    ngx_msec_int_t check_interval);

ngx_int_t ngx_health_detect_check_timeout_is_valid(
    ngx_msec_int_t check_timeout);

ngx_int_t ngx_health_detect_check_keepalive_time_is_valid(
    ngx_msec_int_t keepalive_time);

ngx_uint_t ngx_health_detect_get_policy_alert_method_from_string(
    ngx_str_t *alert_method);

char *ngx_health_detect_api_get_policy_type_to_string(ngx_uint_t type);

ngx_uint_t ngx_health_detect_get_policy_type_from_string(ngx_str_t *type);

ngx_int_t ngx_parse_addr_port_on_slab_pool_locked(
    ngx_slab_pool_t *pool, ngx_addr_t *addr, u_char *text, size_t len);
#endif  // NGX_HEALTH_DETECT_MODULE_COMMON_H_