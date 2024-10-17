#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "cJSON.h"
#include "ngx_health_detect_common.h"
#include "ngx_health_detect_utils.h"

typedef struct {
    ngx_uint_t max_history_status_count;
    size_t check_shm_size;

    ngx_health_detect_peers_manager_t *peers_manager;
} ngx_stream_health_detect_main_conf_t;

typedef struct {
    ngx_str_t send_content;
    ngx_health_detect_policy_data_t data;
} ngx_stream_health_detect_srv_conf_t;

#define peers_manager_ctx stream_peers_manager_ctx
ngx_health_detect_peers_manager_t *peers_manager_ctx = NULL;

static void *ngx_stream_health_detect_create_main_conf(ngx_conf_t *cf);
static char *ngx_stream_health_detect_init_main_conf(
    ngx_conf_t *cf, void *conf);
static void *ngx_stream_health_detect_create_srv_conf(ngx_conf_t *cf);

static char *ngx_stream_health_detect_init_shm(
    ngx_conf_t *cf, void *conf, ngx_str_t *zone_name, ngx_int_t size);

ngx_health_detect_default_detect_policy_t *
ngx_stream_health_detect_get_default_detect_policy(ngx_uint_t type);

static void ngx_stream_health_detect_free_node(ngx_rbtree_node_t *node);
static void ngx_stream_health_detect_shm_free_node(ngx_rbtree_node_t *node);
static ngx_rbtree_node_t *ngx_stream_health_detect_peers_rbtree_lookup(
    uint32_t hash, ngx_str_t *key);
ngx_rbtree_node_t *ngx_stream_health_detect_peers_shm_rbtree_lookup(
    uint32_t hash, ngx_str_t *key);
ngx_int_t ngx_stream_health_detect_add_or_update_node(
    ngx_health_detect_detect_policy_t *policy);
static ngx_int_t ngx_stream_health_detect_add_or_update_node_on_shm(
    ngx_health_detect_detect_policy_t *policy);
ngx_int_t ngx_stream_health_detect_delete_node(ngx_str_t *key);
ngx_int_t ngx_stream_health_detect_delete_all_node();
static ngx_int_t ngx_stream_health_detect_status_update(
    ngx_rbtree_node_t *node, ngx_uint_t result);

static ngx_int_t ngx_stream_health_detect_add_timer(ngx_rbtree_node_t *node);
static ngx_int_t ngx_stream_health_detect_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_stream_health_detect_need_exit();

static void ngx_stream_health_detect_clean_timeout_event_and_connection(
    ngx_health_detect_peer_t *peer);

static void ngx_stream_health_detect_peek_handler(ngx_event_t *event);
static void ngx_stream_health_detect_send_handler(ngx_event_t *event);
static void ngx_stream_health_detect_recv_handler(ngx_event_t *event);

ngx_int_t ngx_http_health_detect_http_init(ngx_health_detect_peer_t *peer);

ngx_int_t ngx_http_health_detect_http_parse(ngx_health_detect_peer_t *peer);
void ngx_http_health_detect_http_reinit(ngx_health_detect_peer_t *peer);
void ngx_http_health_detect_ssl_hello_reinit(ngx_health_detect_peer_t *peer);
ngx_int_t ngx_http_health_detect_ssl_hello_parse(
    ngx_health_detect_peer_t *peer);
ngx_int_t ngx_http_health_detect_ssl_hello_init(ngx_health_detect_peer_t *peer);
ngx_int_t ngx_http_health_detect_peek_one_byte(ngx_connection_t *c);

static void ngx_stream_health_detect_peer_rbtree_insert_value(
    ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);
static void ngx_stream_health_detect_peer_shm_rbtree_insert_value(
    ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);

static char *ngx_stream_health_detect_set_max_history_status_count(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_health_detect_set_shm_size(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_health_detect_upstream_check(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_health_detect_http_send(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_health_detect_http_expect_alive(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_conf_bitmask_t ngx_check_http_expect_alive_masks[] = {
    {ngx_string("http_2xx"), NGX_CHECK_HTTP_2XX},
    {ngx_string("http_3xx"), NGX_CHECK_HTTP_3XX},
    {ngx_string("http_4xx"), NGX_CHECK_HTTP_4XX},
    {ngx_string("http_5xx"), NGX_CHECK_HTTP_5XX},
    {ngx_string("http_err"), NGX_CHECK_HTTP_ERR}, {ngx_null_string, 0}};

static ngx_health_detect_default_detect_policy_t
    ngx_health_detect_default_detect_policy[] = {
        {NGX_HTTP_CHECK_TCP, ngx_string("tcp"), ngx_null_string, 0,
            ngx_string("log"), 1, 2, ngx_stream_health_detect_peek_handler,
            ngx_stream_health_detect_peek_handler, NULL, NULL, NULL, 0, 0,
            3600000, 30000, 3000},
        {NGX_HTTP_CHECK_HTTP, ngx_string("http"),
            ngx_string("GET / HTTP/1.0\r\n\r\n"),
            NGX_CONF_BITMASK_SET | NGX_CHECK_HTTP_2XX | NGX_CHECK_HTTP_3XX,
            ngx_string("log"), 1, 2, ngx_stream_health_detect_send_handler,
            ngx_stream_health_detect_recv_handler,
            ngx_http_health_detect_http_init, ngx_http_health_detect_http_parse,
            ngx_http_health_detect_http_reinit, 1, 1, 3600000, 30000, 3000},
        {NGX_HTTP_CHECK_SSL_HELLO, ngx_string("https"),
            ngx_string(ngx_http_health_sslv3_client_hello_pkt), 0,
            ngx_string("log"), 1, 2, ngx_stream_health_detect_send_handler,
            ngx_stream_health_detect_recv_handler,
            ngx_http_health_detect_ssl_hello_init,
            ngx_http_health_detect_ssl_hello_parse,
            ngx_http_health_detect_ssl_hello_reinit, 1, 0, 0, 30000, 3000},
        {0, ngx_null_string, ngx_null_string, 0, ngx_null_string, 0, 0, NULL,
            NULL, NULL, NULL, NULL, 0, 0, 0, 30000, 3000}};

static ngx_command_t ngx_stream_health_detect_cmds[] = {
    {ngx_string("health_detect_check"), NGX_STREAM_UPS_CONF | NGX_CONF_1MORE,
        ngx_stream_health_detect_upstream_check, 0, 0, NULL},
    {ngx_string("health_detect_http_send"),
        NGX_STREAM_UPS_CONF | NGX_CONF_TAKE1,
        ngx_stream_health_detect_http_send, 0, 0, NULL},
    {ngx_string("health_detect_http_expect_alive"),
        NGX_STREAM_UPS_CONF | NGX_CONF_1MORE,
        ngx_stream_health_detect_http_expect_alive, 0, 0, NULL},
    {ngx_string("health_detect_max_history_status_count"),
        NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_stream_health_detect_set_max_history_status_count, 0, 0, NULL},
    {ngx_string("health_detect_shm_size"),
        NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_stream_health_detect_set_shm_size, 0, 0, NULL},
    ngx_null_command};

static ngx_stream_module_t ngx_stream_health_detect_modules_ctx = {NULL, NULL,
    ngx_stream_health_detect_create_main_conf,
    ngx_stream_health_detect_init_main_conf,
    ngx_stream_health_detect_create_srv_conf, NULL};

ngx_module_t ngx_stream_health_detect_module = {NGX_MODULE_V1,
    &ngx_stream_health_detect_modules_ctx, ngx_stream_health_detect_cmds,
    NGX_STREAM_MODULE, NULL, NULL, ngx_stream_health_detect_init_process, NULL,
    NULL, NULL, NULL, NGX_MODULE_V1_PADDING};

static void *
ngx_stream_health_detect_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_health_detect_main_conf_t *hdmcf;
    ngx_health_detect_peers_t *peers;

    hdmcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_health_detect_main_conf_t));
    if (hdmcf == NULL) {
        return NULL;
    }

    hdmcf->max_history_status_count = NGX_CONF_UNSET_UINT;
    hdmcf->check_shm_size = NGX_CONF_UNSET_SIZE;

    hdmcf->peers_manager =
        ngx_pcalloc(cf->pool, sizeof(ngx_health_detect_peers_manager_t));
    if (hdmcf->peers_manager == NULL) {
        return NULL;
    }

    peers = ngx_pcalloc(cf->pool, sizeof(ngx_health_detect_peers_t));
    if (peers == NULL) {
        return NULL;
    }

    ngx_rbtree_init(&peers->rbtree, &peers->sentinel,
        ngx_stream_health_detect_peer_rbtree_insert_value);

    peers->checksum = 0;
    hdmcf->peers_manager->peers = peers;

    peers_manager_ctx = hdmcf->peers_manager;
    peers_manager_ctx->hdmcf = hdmcf;

    return hdmcf;
}

static char *
ngx_stream_health_detect_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_str_t shm_zone_name;

    ngx_stream_health_detect_main_conf_t *hdmcf = conf;
    ngx_str_set(&shm_zone_name, "ngx stream health detect");

    if (hdmcf->max_history_status_count == NGX_CONF_UNSET_UINT) {
        hdmcf->max_history_status_count = MAX_STATUS_CHANGE_COUNT_DEFAULT_VALUE;
    }

    if (hdmcf->check_shm_size == NGX_CONF_UNSET_SIZE) {
        hdmcf->check_shm_size = DEFAULT_CHECK_SHM_SIZE;
    }

    ngx_log_error(NGX_LOG_INFO, cf->log, 0,
        "ngx stream health detect module: check_zone name(%V) size(%ui)M ",
        &shm_zone_name, hdmcf->check_shm_size / 1024 / 1024);

    return ngx_stream_health_detect_init_shm(
        cf, conf, &shm_zone_name, hdmcf->check_shm_size);
}

static void *
ngx_stream_health_detect_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_health_detect_srv_conf_t *hdscf;

    hdscf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_health_detect_srv_conf_t));
    if (hdscf == NULL) {
        return NULL;
    }
    ngx_str_null(&hdscf->send_content);

    hdscf->data.type = NGX_CONF_UNSET_UINT;
    hdscf->data.alert_method = NGX_CONF_UNSET_UINT;
    hdscf->data.expect_response_status.http_status = NGX_CONF_UNSET_UINT;
    hdscf->data.fall = NGX_CONF_UNSET_UINT;
    hdscf->data.rise = NGX_CONF_UNSET_UINT;
    hdscf->data.check_interval = NGX_CONF_UNSET_MSEC;
    hdscf->data.check_timeout = NGX_CONF_UNSET;
    hdscf->data.need_keepalive = NGX_CONF_UNSET;
    hdscf->data.keepalive_time = NGX_CONF_UNSET_MSEC;

    return hdscf;
}

static char *
ngx_stream_health_detect_upstream_check(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value, s;
    ngx_uint_t i;
    ngx_stream_health_detect_srv_conf_t *hdscf;
    ngx_uint_t default_down;

    default_down = 0;
    value = cf->args->elts;

    hdscf = ngx_stream_conf_get_module_srv_conf(
        cf, ngx_stream_health_detect_module);
    if (hdscf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "type=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            hdscf->data.type =
                ngx_health_detect_get_policy_type_from_string(&s);

            if (!hdscf->data.type) {
                goto invalid_check_parameter;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "alert_method=", 13) == 0) {
            s.len = value[i].len - 13;
            s.data = value[i].data + 13;

            hdscf->data.alert_method =
                ngx_health_detect_get_policy_alert_method_from_string(&s);

            if (!hdscf->data.alert_method) {
                goto invalid_check_parameter;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "default_down=", 13) == 0) {
            s.len = value[i].len - 13;
            s.data = value[i].data + 13;

            if (ngx_strcasecmp(s.data, (u_char *) "true") == 0) {
                default_down = 1;
            } else if (ngx_strcasecmp(s.data, (u_char *) "false") == 0) {
                default_down = 0;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid value \"%s\", "
                    "it must be \"true\" or \"false\"",
                    value[i].data);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "rise=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            hdscf->data.rise = ngx_atoi(s.data, s.len);
            if (hdscf->data.rise == (ngx_uint_t) NGX_ERROR ||
                !ngx_health_detect_check_fall_rise_is_valid(hdscf->data.rise)) {
                goto invalid_check_parameter;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "fall=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            hdscf->data.fall = ngx_atoi(s.data, s.len);
            if (hdscf->data.fall == (ngx_uint_t) NGX_ERROR ||
                !ngx_health_detect_check_fall_rise_is_valid(hdscf->data.fall)) {
                goto invalid_check_parameter;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            hdscf->data.check_interval = ngx_atoi(s.data, s.len);
            if (hdscf->data.check_interval == (ngx_msec_t) NGX_ERROR ||
                !ngx_health_detect_check_interval_is_valid(
                    hdscf->data.check_interval)) {
                goto invalid_check_parameter;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            hdscf->data.check_timeout = ngx_atoi(s.data, s.len);
            if (hdscf->data.check_timeout == (ngx_msec_t) NGX_ERROR ||
                !ngx_health_detect_check_timeout_is_valid(
                    hdscf->data.check_timeout)) {
                goto invalid_check_parameter;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "keepalive=", 10) == 0) {
            s.len = value[i].len - 10;
            s.data = value[i].data + 10;

            if (ngx_strcasecmp(s.data, (u_char *) "true") == 0) {
                hdscf->data.need_keepalive = 1;
            } else if (ngx_strcasecmp(s.data, (u_char *) "false") == 0) {
                hdscf->data.need_keepalive = 0;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid value \"%s\", "
                    "it must be \"true\" or \"false\"",
                    value[i].data);
                return NGX_CONF_ERROR;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "keepalive_time=", 15) == 0) {
            s.len = value[i].len - 15;
            s.data = value[i].data + 15;

            hdscf->data.keepalive_time = ngx_atoi(s.data, s.len);
            if (hdscf->data.keepalive_time == (ngx_msec_t) NGX_ERROR ||
                !ngx_health_detect_check_keepalive_time_is_valid(
                    hdscf->data.keepalive_time)) {
                goto invalid_check_parameter;
            }
            continue;
        }

        goto invalid_check_parameter;
    }

    hdscf->data.default_down = default_down;
    if (hdscf->data.type == NGX_CONF_UNSET_UINT) {
        hdscf->data.type = NGX_HTTP_CHECK_TCP;
    }
    return NGX_CONF_OK;

invalid_check_parameter:

    ngx_conf_log_error(
        NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}

static char *
ngx_stream_health_detect_http_send(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_stream_health_detect_srv_conf_t *hdscf;

    value = cf->args->elts;

    hdscf = ngx_stream_conf_get_module_srv_conf(
        cf, ngx_stream_health_detect_module);

    if (hdscf->data.type == NGX_CONF_UNSET_UINT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid health_detect_http_send should set "
            "[health_detect_check] first");
        return NGX_CONF_ERROR;
    }

    if (value[1].len && hdscf->data.type != NGX_HTTP_CHECK_HTTP) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "health_detect_http_send is valid when detect type is http");
        return NGX_CONF_ERROR;
    }

    hdscf->send_content = value[1];

    return NGX_CONF_OK;
}

static char *
ngx_stream_health_detect_http_expect_alive(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_uint_t bit, i, m;
    ngx_conf_bitmask_t *mask;
    ngx_stream_health_detect_srv_conf_t *hdscf;

    value = cf->args->elts;
    mask = ngx_check_http_expect_alive_masks;

    hdscf =
        ngx_http_conf_get_module_srv_conf(cf, ngx_stream_health_detect_module);
    bit = 0;

    for (i = 1; i < cf->args->nelts; i++) {
        for (m = 0; mask[m].name.len != 0; m++) {
            if (mask[m].name.len != value[i].len ||
                ngx_strcasecmp(mask[m].name.data, value[i].data) != 0) {
                continue;
            }

            if (bit & mask[m].mask) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                    "duplicate value \"%s\"", value[i].data);

            } else {
                bit |= mask[m].mask;
            }

            break;
        }

        if (mask[m].name.len == 0) {
            ngx_conf_log_error(
                NGX_LOG_WARN, cf, 0, "invalid value \"%s\"", value[i].data);

            return NGX_CONF_ERROR;
        }
    }

    hdscf->data.expect_response_status.http_status = bit;

    return NGX_CONF_OK;
}

static char *
ngx_stream_health_detect_set_max_history_status_count(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;

    ngx_stream_health_detect_main_conf_t *hdmcf;

    hdmcf = ngx_stream_conf_get_module_main_conf(
        cf, ngx_stream_health_detect_module);

    if (hdmcf->max_history_status_count != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }
    value = cf->args->elts;

    hdmcf->max_history_status_count = ngx_atoi(value[1].data, value[1].len);
    if (hdmcf->max_history_status_count == (ngx_uint_t) NGX_ERROR ||
        hdmcf->max_history_status_count > MAX_STATUS_CHANGE_COUNT_MAX_VALUE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid value \"%s\" in \"%s\" directive, max: %i", value[1].data,
            cmd->name.data, MAX_STATUS_CHANGE_COUNT_MAX_VALUE);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_stream_health_detect_set_shm_size(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_stream_health_detect_main_conf_t *ucmcf;

    ucmcf = ngx_stream_conf_get_module_main_conf(
        cf, ngx_stream_health_detect_module);
    if (ucmcf->check_shm_size != NGX_CONF_UNSET_SIZE) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ucmcf->check_shm_size = ngx_parse_size(&value[1]);
    if (ucmcf->check_shm_size == (size_t) NGX_ERROR) {
        return "invalid value";
    }

    return NGX_CONF_OK;
}

static void
ngx_stream_health_detect_send_handler(ngx_event_t *event)
{
    ssize_t size;
    ngx_connection_t *c;
    ngx_health_detect_peer_t *peer;
    ngx_http_check_data_ctx_t *ctx;
    ngx_rbtree_node_t *node;

    if (ngx_stream_health_detect_need_exit()) {
        return;
    }

    c = event->data;
    node = c->data;
    peer = (ngx_health_detect_peer_t *) (&node->color);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, event->log, 0, "http check send.");

    if (c->pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, event->log, 0,
            "check pool NULL with peer: %V ", &peer->policy->peer_addr.name);

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
            ngx_log_debug2(NGX_LOG_DEBUG_STREAM, event->log, err,
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
        ngx_log_debug0(
            NGX_LOG_DEBUG_STREAM, event->log, 0, "http check send done.");

        peer->state = NGX_HTTP_CHECK_SEND_DONE;
    }

    return;

check_send_fail:
    if (ngx_stream_health_detect_status_update(node, NGX_CHECK_STATUS_DOWN) ==
        NGX_DONE) {
        return;
    }
    ngx_stream_health_detect_clean_timeout_event_and_connection(peer);
}

static void
ngx_stream_health_detect_recv_handler(ngx_event_t *event)
{
    u_char *new_buf;
    ssize_t size, n;
    ngx_int_t rc;
    ngx_connection_t *c;
    ngx_http_check_data_ctx_t *ctx;
    ngx_health_detect_peer_t *peer;
    ngx_rbtree_node_t *node;

    if (ngx_stream_health_detect_need_exit()) {
        return;
    }

    c = event->data;
    node = c->data;
    peer = (ngx_health_detect_peer_t *) (&node->color);

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
#if (NGX_DEBUG)
        {
            ngx_err_t err;
            rc = peer->default_policy->parse(peer);
            err = (size >= 0) ? 0 : ngx_socket_errno;
            ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, err,
                "http check parse rc: %i, peer: %V ", rc,
                &peer->policy->peer_addr.name);
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

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
        "http check parse rc: %i, peer: %V ", rc,
        &peer->policy->peer_addr.name);

    switch (rc) {
        case NGX_AGAIN:
            /* The peer has closed its half side of the connection */
            if (size == 0) {
                rc = ngx_stream_health_detect_status_update(
                    node, NGX_CHECK_STATUS_DOWN);
                c->error = 1;
            }

            return;

        case NGX_ERROR:
            ngx_log_error(NGX_LOG_ERR, event->log, 0,
                "check protocol %ui error with peer: %V ",
                peer->policy->data.type, &peer->policy->peer_addr.name);

            rc = ngx_stream_health_detect_status_update(
                node, NGX_CHECK_STATUS_DOWN);
            break;

        case NGX_OK:
            /* fall through */

        default:
            rc = ngx_stream_health_detect_status_update(
                node, NGX_CHECK_STATUS_UP);
            break;
    }

    peer->state = NGX_HTTP_CHECK_RECV_DONE;
    if (rc != NGX_DONE) {
        ngx_stream_health_detect_clean_timeout_event_and_connection(peer);
    }
    return;

check_recv_fail:
    rc = ngx_stream_health_detect_status_update(node, NGX_CHECK_STATUS_DOWN);
    if (rc != NGX_DONE) {
        ngx_stream_health_detect_clean_timeout_event_and_connection(peer);
    }
}

static void
ngx_stream_health_detect_finish_handler(ngx_health_detect_peer_t *peer)
{
    if (ngx_stream_health_detect_need_exit()) {
        return;
    }
}

static void
ngx_stream_health_detect_peek_handler(ngx_event_t *event)
{
    ngx_connection_t *c;
    ngx_health_detect_peer_t *peer;
    ngx_int_t rc;
    ngx_rbtree_node_t *node;

    if (ngx_stream_health_detect_need_exit()) {
        return;
    }

    c = event->data;
    node = c->data;
    peer = (ngx_health_detect_peer_t *) (&node->color);

    if (ngx_http_health_detect_peek_one_byte(c) == NGX_OK) {
        rc = ngx_stream_health_detect_status_update(node, NGX_CHECK_STATUS_UP);
    } else {
        c->error = 1;
        rc =
            ngx_stream_health_detect_status_update(node, NGX_CHECK_STATUS_DOWN);
    }

    ngx_log_debug1(
        NGX_LOG_DEBUG_STREAM, event->log, 0, "peek handler result(%ui)", rc);

    if (rc != NGX_DONE) {
        ngx_stream_health_detect_clean_timeout_event_and_connection(peer);
        ngx_stream_health_detect_finish_handler(peer);
    }
}

static void
ngx_stream_health_detect_clear_one_peer_all_events(
    ngx_health_detect_peer_t *peer)
{
    ngx_connection_t *c;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0,
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

static void
ngx_stream_health_detect_clear_peers_events()
{
    ngx_rbtree_node_t *node;
    ngx_rbtree_node_t *sentinel;
    ngx_health_detect_peers_t *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0,
        "clear all the events on %P ", ngx_pid);

    peers = peers_manager_ctx->peers;

    node = peers->rbtree.root;
    sentinel = peers->rbtree.sentinel;
    while (node != sentinel) {
        ngx_stream_health_detect_free_node(node);

        node = peers->rbtree.root;
    }
}

static ngx_int_t
ngx_stream_health_detect_need_exit()
{
    if (ngx_terminate || ngx_exiting || ngx_quit) {
        ngx_stream_health_detect_clear_peers_events();
        return 1;
    }

    return 0;
}

static void
ngx_stream_health_detect_discard_handler(ngx_event_t *event)
{
    u_char buf[4096];
    ssize_t size;
    ngx_connection_t *c;
    ngx_health_detect_peer_t *peer;
    ngx_rbtree_node_t *node;

    if (ngx_stream_health_detect_need_exit()) {
        return;
    }

    c = event->data;

    node = c->data;
    peer = (ngx_health_detect_peer_t *) (&node->color);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0,
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
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
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
    ngx_stream_health_detect_clean_timeout_event_and_connection(peer);
}

static void
ngx_stream_health_detect_dummy_handler(ngx_event_t *event)
{
    return;
}

static void
ngx_stream_health_detect_clean_timeout_event_and_connection(
    ngx_health_detect_peer_t *peer)
{
    ngx_connection_t *c;
    c = peer->pc.connection;

    if (c) {
        if (c->error == 0 && peer->policy->data.need_keepalive &&
            (ngx_current_msec - peer->pc.start_time <
                peer->policy->data.keepalive_time)) {
            c->write->handler = ngx_stream_health_detect_dummy_handler;
            c->read->handler = ngx_stream_health_detect_discard_handler;
        } else {
            ngx_close_connection(c);
            peer->pc.connection = NULL;
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                "close connection on clean timeout event and connection func");
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
ngx_stream_health_detect_peer_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t **p;
    ngx_health_detect_peer_t *lrn, *lrnt;

    for (;;) {
        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else { /* node->key == temp->key */

            lrn = (ngx_health_detect_peer_t *) &node->color;
            lrnt = (ngx_health_detect_peer_t *) &temp->color;

            p = (ngx_memn2cmp(lrn->policy->peer_name.data,
                     lrnt->policy->peer_name.data, lrn->policy->peer_name.len,
                     lrnt->policy->peer_name.len) < 0)
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
ngx_stream_health_detect_peers_rbtree_lookup(uint32_t hash, ngx_str_t *key)
{
    ngx_rbtree_node_t *node, *sentinel;
    ngx_health_detect_peer_t *peer;
    ngx_health_detect_peers_t *peers;

    peers = peers_manager_ctx->peers;

    node = peers->rbtree.root;
    sentinel = peers->rbtree.sentinel;

    while (node != sentinel) {
        if (node->key != hash) {
            node = (node->key > hash) ? node->left : node->right;
            continue;
        }

        peer = (ngx_health_detect_peer_t *) &node->color;
        if (peer->policy->peer_name.len != key->len) {
            node = (peer->policy->peer_name.len < key->len) ? node->left
                                                            : node->right;
            continue;
        }

        /* hash == node->key */
        ngx_int_t rc =
            ngx_memcmp(peer->policy->peer_name.data, key->data, key->len);
        if (rc == 0) {
            return node;
        }
        node = (rc > 0) ? node->left : node->right;
    }

    return NULL;
}

static void
ngx_stream_health_detect_peer_shm_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t **p;
    ngx_health_detect_peer_shm_t *lrn, *lrnt;

    for (;;) {
        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else { /* node->key == temp->key */

            lrn = (ngx_health_detect_peer_shm_t *) &node->color;
            lrnt = (ngx_health_detect_peer_shm_t *) &temp->color;

            p = (ngx_memn2cmp(lrn->policy.peer_name.data,
                     lrnt->policy.peer_name.data, lrn->policy.peer_name.len,
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

ngx_rbtree_node_t *
ngx_stream_health_detect_peers_shm_rbtree_lookup(uint32_t hash, ngx_str_t *key)
{
    ngx_rbtree_node_t *node_shm, *sentinel;
    ngx_health_detect_peer_shm_t *peer_shm;
    ngx_health_detect_peers_shm_t *peers_shm;

    peers_shm = peers_manager_ctx->peers_shm;

    node_shm = peers_shm->rbtree.root;
    sentinel = peers_shm->rbtree.sentinel;

    while (node_shm != sentinel) {
        if (node_shm->key != hash) {
            node_shm =
                (node_shm->key > hash) ? node_shm->left : node_shm->right;
            continue;
        }

        peer_shm = (ngx_health_detect_peer_shm_t *) &node_shm->color;
        if (peer_shm->policy.peer_name.len != key->len) {
            node_shm = (peer_shm->policy.peer_name.len < key->len)
                           ? node_shm->left
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

static void
ngx_stream_health_detect_shm_free_node(ngx_rbtree_node_t *node)
{
    ngx_slab_pool_t *shpool;
    ngx_health_detect_peers_shm_t *peers_shm;
    ngx_queue_t *q;
    ngx_health_detect_one_peer_status *status;
    ngx_health_detect_peer_shm_t *peer_shm;

    peer_shm = (ngx_health_detect_peer_shm_t *) &node->color;
    if (peer_shm->policy.data.from_upstream) {
        peer_shm->ref--;

        if (peer_shm->ref > 0) {
            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                "on free shm node: peer name:%V ref(%ui) not zero, so do not "
                "delete this node",
                &peer_shm->policy.peer_name, peer_shm->ref);
            return;
        }
    }

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
        "on free shm node: peer name:%V ref(%ui) is zero, so delete this node",
        &peer_shm->policy.peer_name, peer_shm->ref);

    peers_shm = peers_manager_ctx->peers_shm;
    shpool = peers_shm->shpool;

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

static ngx_int_t
ngx_stream_health_detect_add_or_update_node_on_shm(
    ngx_health_detect_detect_policy_t *policy)
{
    ngx_slab_pool_t *shpool;
    ngx_health_detect_peers_shm_t *peers_shm;
    uint32_t hash;
    ngx_rbtree_node_t *node_shm;
    ngx_health_detect_peer_shm_t *peer_shm;
    ngx_int_t rc;
    ngx_stream_health_detect_main_conf_t *hdmcf;

    if (peers_manager_ctx == NULL) {
        return NGX_ERROR;
    }

    hdmcf = peers_manager_ctx->hdmcf;

    peers_shm = peers_manager_ctx->peers_shm;
    shpool = peers_shm->shpool;

    hash = ngx_crc32_short(policy->peer_name.data, policy->peer_name.len);
    ngx_shmtx_lock(&shpool->mutex);
    node_shm = ngx_stream_health_detect_peers_shm_rbtree_lookup(
        hash, &policy->peer_name);
    if (node_shm != NULL) {
        peer_shm = (ngx_health_detect_peer_shm_t *) &node_shm->color;
        if (peer_shm->policy.checksum == policy->checksum) {
            if (policy->data.from_upstream) {
                peer_shm->ref++;
            }
            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                "on shm: op(add/update) node peer name(%V) already exist and "
                "policy is same, just add ref(%ui)",
                &policy->peer_name, peer_shm->ref);
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            "on shm: op(add/update) node peer name(%V) already exist but "
            "policy id diff, so delete old node then add node",
            &policy->peer_name);
        ngx_stream_health_detect_shm_free_node(node_shm);
    }

    if (peers_shm->number >= peers_shm->max_number) {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            "on shm: op(add/update) the number of nodes(%ui) being "
            "checked exceeds the upper limit(%ui)",
            peers_shm->number, peers_shm->max_number);
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_ERROR;
    }

    size_t size = offsetof(ngx_rbtree_node_t, color) +
                  sizeof(ngx_health_detect_peer_shm_t);

    node_shm = ngx_slab_calloc_locked(shpool, size);
    if (node_shm == NULL) {
        goto failed;
    }
    node_shm->key = hash;

    peer_shm = (ngx_health_detect_peer_shm_t *) &node_shm->color;

    peer_shm->policy.data = policy->data;
    peer_shm->policy.checksum = policy->checksum;

    if (peer_shm->policy.data.from_upstream) {
        peer_shm->ref++;
    }

    rc = ngx_parse_addr_port_on_slab_pool_locked(shpool,
        &peer_shm->policy.peer_addr, policy->peer_addr.name.data,
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
        ngx_memcpy(peer_shm->policy.send_content.data,
            policy->send_content.data, policy->send_content.len);
        peer_shm->policy.send_content.len = policy->send_content.len;
    } else {
        ngx_str_null(&peer_shm->policy.send_content);
    }
    ngx_queue_init(&peer_shm->status.history_status);

    if (policy->data.default_down) {
        peer_shm->status.latest_status = NGX_CHECK_STATUS_DOWN;
    } else {
        peer_shm->status.latest_status = NGX_CHECK_STATUS_UP;
    }

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

    peer_shm->status.max_status_count = hdmcf->max_history_status_count;
    peer_shm->status.current_status_count = 0;

    peer_shm->owner = NGX_INVALID_PID;
    peer_shm->access_time = ngx_current_msec;
    ngx_rbtree_insert(&peers_shm->rbtree, node_shm);
    peers_shm->number++;
    peers_shm->checksum += policy->checksum;
    ngx_shmtx_unlock(&shpool->mutex);

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
        "on shm: op(add/update) add node peer name(%V) peer addr(%V) ref(%ui)",
        &policy->peer_name, &policy->peer_addr.name, peer_shm->ref);
    return NGX_OK;

failed:
    if (node_shm) {
        ngx_stream_health_detect_shm_free_node(node_shm);
    }

    ngx_shmtx_unlock(&shpool->mutex);
    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
        "on shm: op(add/update) node peer name(%V) failed", &policy->peer_name);

    return NGX_ERROR;
}

static ngx_int_t
ngx_stream_health_detect_add_or_update_node_on_local(
    ngx_health_detect_detect_policy_t *policy, ngx_uint_t start_detect_timer)
{
    uint32_t hash;
    ngx_health_detect_peer_t *opeer;
    ngx_int_t rc;
    ngx_rbtree_node_t *node;
    ngx_health_detect_peer_t *peer;
    size_t peer_size, peer_policy_max_size;
    ngx_pool_t *temp_pool;

    if (peers_manager_ctx == NULL) {
        return NGX_ERROR;
    }

    hash = ngx_crc32_short(policy->peer_name.data, policy->peer_name.len);
    node =
        ngx_stream_health_detect_peers_rbtree_lookup(hash, &policy->peer_name);
    if (node != NULL) {
        opeer = (ngx_health_detect_peer_t *) &node->color;
        if (opeer->policy->checksum == policy->checksum) {
            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                "on local: op(add/update) node peer name(%V) already exist and "
                "policy is same, so do nothing",
                &policy->peer_name);

            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            "on local: op(add/update) node peer name(%V) already exist but "
            "policy id diff, so delete old node then add node",
            &policy->peer_name);
        ngx_stream_health_detect_free_node(node);
    }

    peer_size =
        offsetof(ngx_rbtree_node_t, color) + sizeof(ngx_health_detect_peer_t);
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
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "on local: op(add/update) create pool error");
    }

    node = ngx_pcalloc(temp_pool, peer_size);
    if (node == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "on local: op(add/update) calloc error");
        return NGX_ERROR;
    }

    node->key = hash;

    peer = (ngx_health_detect_peer_t *) &node->color;
    peer->temp_pool = temp_pool;

    peer->default_policy =
        ngx_stream_health_detect_get_default_detect_policy(policy->data.type);

    peer->policy =
        ngx_pcalloc(peer->temp_pool, sizeof(ngx_health_detect_detect_policy_t));

    peer->policy->data = policy->data;
    peer->policy->checksum = policy->checksum;

    rc = ngx_parse_addr_port(peer->temp_pool, &peer->policy->peer_addr,
        policy->peer_addr.name.data, policy->peer_addr.name.len);
    if (rc == NGX_ERROR || rc == NGX_DECLINED) {
        goto failed;
    }

    u_char *q = ngx_pnalloc(peer->temp_pool, NGX_SOCKADDR_STRLEN);
    if (q == NULL) {
        return NGX_ERROR;
    }

    size_t len = ngx_sock_ntop(peer->policy->peer_addr.sockaddr,
        peer->policy->peer_addr.socklen, q, NGX_SOCKADDR_STRLEN, 1);
    peer->policy->peer_addr.name.len = len;
    peer->policy->peer_addr.name.data = q;

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

    peers_manager_ctx->peers->checksum += policy->checksum;

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
        "on local: op(add/update) add node peer name(%V) peer addr(%V)",
        &policy->peer_name, &policy->peer_addr.name);

    if (start_detect_timer) {
        rc = ngx_stream_health_detect_add_timer(node);
        if (rc != NGX_OK) {
            goto failed;
        }
    }

    return NGX_OK;

failed:
    if (node) {
        ngx_stream_health_detect_free_node(node);
    }

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
        "on local: op(add/update) node key(%V) failed", &policy->peer_name);

    return NGX_ERROR;
}

ngx_int_t
ngx_stream_health_detect_add_or_update_node(
    ngx_health_detect_detect_policy_t *policy)
{
    ngx_int_t rc;

    rc = ngx_stream_health_detect_add_or_update_node_on_shm(policy);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_stream_health_detect_add_or_update_node_on_local(policy, 1);
}

static void
ngx_stream_health_detect_free_node(ngx_rbtree_node_t *node)
{
    ngx_health_detect_peer_t *peer;

    if (peers_manager_ctx == NULL) {
        return;
    }

    peer = (ngx_health_detect_peer_t *) &node->color;

    ngx_stream_health_detect_clear_one_peer_all_events(peer);

    ngx_rbtree_delete(&peers_manager_ctx->peers->rbtree, node);

    if (peer->temp_pool != NULL) {
        ngx_destroy_pool(peer->temp_pool);
    }
}

ngx_int_t
ngx_stream_health_detect_delete_node(ngx_str_t *key)
{
    ngx_rbtree_node_t *node_shm, *node;
    ngx_slab_pool_t *shpool;
    uint32_t hash;

    if (peers_manager_ctx == NULL) {
        return NGX_ERROR;
    }

    shpool = peers_manager_ctx->peers_shm->shpool;
    hash = ngx_crc32_short(key->data, key->len);

    ngx_shmtx_lock(&shpool->mutex);
    node_shm = ngx_stream_health_detect_peers_shm_rbtree_lookup(hash, key);
    if (node_shm != NULL) {
        ngx_stream_health_detect_shm_free_node(node_shm);
    } else {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            "on shm: op(delete) node key:%V not found, do noting", key);
    }

    node = ngx_stream_health_detect_peers_rbtree_lookup(hash, key);
    if (node != NULL) {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            "on local: op(delete) node key:%V found, delete this node", key);
        ngx_stream_health_detect_free_node(node);
    } else {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            "on local: op(delete) node key:%V not found, do noting", key);
    }

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}

ngx_int_t
ngx_stream_health_detect_delete_all_node()
{
    ngx_rbtree_node_t *node_shm, *sentinel;
    ngx_health_detect_peers_shm_t *peers_shm;

    if (peers_manager_ctx == NULL) {
        return NGX_ERROR;
    }

    peers_shm = peers_manager_ctx->peers_shm;
    ngx_shmtx_lock(&peers_shm->shpool->mutex);

    node_shm = peers_shm->rbtree.root;
    sentinel = peers_shm->rbtree.sentinel;
    while (node_shm != sentinel) {
        ngx_stream_health_detect_shm_free_node(node_shm);
        node_shm = peers_shm->rbtree.root;
    }
    ngx_shmtx_unlock(&peers_shm->shpool->mutex);

    ngx_stream_health_detect_clear_peers_events();

    return NGX_OK;
}

ngx_uint_t
ngx_stream_health_detect_get_down_count()
{
    ngx_health_detect_peers_shm_t *peers_shm;
    ngx_rbtree_node_t *root_shm, *sentinel_shm, *node_shm;
    ngx_health_detect_peer_shm_t *peer_shm;
    ngx_uint_t down_count;
    peers_shm = peers_manager_ctx->peers_shm;

    down_count = 0;
    root_shm = peers_shm->rbtree.root;
    sentinel_shm = peers_shm->rbtree.sentinel;
    if (root_shm != sentinel_shm) {
        for (node_shm = ngx_rbtree_min(root_shm, sentinel_shm); node_shm;
             node_shm = ngx_rbtree_next(&peers_shm->rbtree, node_shm)) {
            peer_shm = (ngx_health_detect_peer_shm_t *) (&node_shm->color);
            if (peer_shm->status.latest_status == NGX_CHECK_STATUS_DOWN) {
                down_count++;
            }
        }
    }

    return down_count;
}

static void
ngx_stream_health_detect_lru_update_status(
    ngx_health_detect_peer_shm_t *peer_shm, ngx_uint_t result)
{
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

static ngx_int_t
ngx_stream_health_detect_status_update(
    ngx_rbtree_node_t *node, ngx_uint_t result)
{
    ngx_health_detect_one_peer_status *add_status;
    ngx_slab_pool_t *shpool;
    ngx_rbtree_node_t *node_shm;
    ngx_health_detect_peer_t *peer;
    ngx_health_detect_peer_shm_t *peer_shm;

    peer = (ngx_health_detect_peer_t *) (&node->color);

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0,
        "on status update: start update peer name(%V) status(%d)",
        &peer->policy->peer_name, result);

    if (peers_manager_ctx == NULL) {
        return NGX_ERROR;
    }

    shpool = peers_manager_ctx->peers_shm->shpool;

    ngx_shmtx_lock(&shpool->mutex);
    node_shm = ngx_stream_health_detect_peers_shm_rbtree_lookup(
        node->key, &peer->policy->peer_name);
    if (node_shm == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_stream_health_detect_free_node(node);
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            "on status update:peer name(%V) not exit in shm, so needn't "
            "update status",
            &peer->policy->peer_name);

        return NGX_DONE;
    }

    peer_shm = (ngx_health_detect_peer_shm_t *) &node_shm->color;
    if (peer_shm->policy.checksum != peer->policy->checksum) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_stream_health_detect_free_node(node);

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
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
            ngx_stream_health_detect_lru_update_status(peer_shm, result);
            ngx_log_debug3(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0,
                "on status update: lru update peer name(%V) status(%d) when "
                "status count over limits(%ui)",
                &peer->policy->peer_name, result,
                peer_shm->status.max_status_count);
            goto done;
        }

        add_status = ngx_slab_calloc_locked(
            shpool, sizeof(ngx_health_detect_one_peer_status));
        if (add_status == NULL) {
            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                "on status update: lru update peer name(%V) status(%d) "
                "when no enough mem to alloc status",
                &peer->policy->peer_name, result);
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }

        add_status->access_time.data = ngx_slab_calloc_locked(
            shpool, peer_shm->status.latest_access_time.len);
        if (add_status->access_time.data == NULL) {
            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                "on status update: lru update peer name(%V) status(%d) "
                "when no enough mem to alloc status",
                &peer->policy->peer_name, result);

            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }

        add_status->access_time.len = peer_shm->status.latest_access_time.len;

        ngx_memcpy(add_status->access_time.data,
            peer_shm->status.latest_access_time.data,
            peer_shm->status.latest_access_time.len);

        add_status->status = peer_shm->status.latest_status;
        ngx_queue_insert_tail(
            &peer_shm->status.history_status, &add_status->link);
        peer_shm->status.current_status_count++;

        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
            "on status update: update peer name(%V) status(%d)",
            &peer->policy->peer_name, result);
    }

done:
    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_OK;
}

static void
ngx_stream_health_detect_timeout_handler(ngx_event_t *event)
{
    ngx_health_detect_peer_t *peer;
    ngx_rbtree_node_t *node;

    if (ngx_stream_health_detect_need_exit()) {
        return;
    }

    node = (ngx_rbtree_node_t *) event->data;
    peer = (ngx_health_detect_peer_t *) (&node->color);

    peer->pc.connection->error = 1;

    ngx_log_error(NGX_LOG_INFO, event->log, 0, "check time out with peer: %V ",
        &peer->policy->peer_name);

    if (ngx_stream_health_detect_status_update(node, NGX_CHECK_STATUS_DOWN) !=
        NGX_DONE) {
        ngx_stream_health_detect_clean_timeout_event_and_connection(peer);
    }
}

static void
ngx_stream_health_detect_connect_handler(ngx_event_t *event)
{
    ngx_int_t rc;
    ngx_connection_t *c;
    ngx_health_detect_peer_t *peer;
    ngx_rbtree_node_t *node;

    if (ngx_stream_health_detect_need_exit()) {
        return;
    }

    node = (ngx_rbtree_node_t *) event->data;
    peer = (ngx_health_detect_peer_t *) (&node->color);

    if (peer->pc.connection != NULL) {
        c = peer->pc.connection;
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0,
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
        ngx_log_error(NGX_LOG_INFO, event->log, 0,
            "on connect handler: connect error(%ui)", rc);

        if (ngx_stream_health_detect_status_update(
                node, NGX_CHECK_STATUS_DOWN) != NGX_DONE) {
            ngx_stream_health_detect_clean_timeout_event_and_connection(peer);
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

static void
ngx_stream_health_detect_start_check_handler(ngx_event_t *event)
{
    ngx_msec_t interval;
    ngx_health_detect_peer_t *peer;
    ngx_slab_pool_t *shpool;
    ngx_rbtree_node_t *node_shm;
    ngx_health_detect_peer_shm_t *peer_shm;
    ngx_rbtree_node_t *node;

    if (ngx_stream_health_detect_need_exit()) {
        return;
    }

    node = (ngx_rbtree_node_t *) event->data;
    peer = (ngx_health_detect_peer_t *) (&node->color);

    shpool = peers_manager_ctx->peers_shm->shpool;

    ngx_shmtx_lock(&shpool->mutex);
    node_shm = ngx_stream_health_detect_peers_shm_rbtree_lookup(
        node->key, &peer->policy->peer_name);
    if (node_shm == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_stream_health_detect_free_node(node);

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            "on start check handler: peer name(%V) not exit in shm, "
            "needn't check again",
            &peer->policy->peer_name);
        return;
    }

    peer_shm = (ngx_health_detect_peer_shm_t *) &node_shm->color;
    if (peer_shm->policy.checksum != peer->policy->checksum) {
        ngx_shmtx_unlock(&shpool->mutex);

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            "on start check handler:peer name(%V) exit in shm but policy is "
            "diff, so needn't check again",
            &peer->policy->peer_name);

        ngx_stream_health_detect_free_node(node);
        return;
    } else {
        if (peer_shm->fast_check_count < peer->policy->data.fall) {
            ngx_add_timer(event, ngx_random() % 500);
        } else {
            ngx_add_timer(event, peer->policy->data.check_interval / 2);
        }

        /* This process is processing this peer now. */
        if (peer_shm->owner == ngx_pid || peer->check_timeout_ev.timer_set) {
            ngx_shmtx_unlock(&shpool->mutex);

            ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0,
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
            ngx_log_debug2(NGX_LOG_DEBUG_STREAM, event->log, 0,
                "time maybe delayed, got current_msec:%M, shm_access_time:%M",
                ngx_current_msec, peer_shm->access_time);
            ngx_shmtx_unlock(&shpool->mutex);
            return;
        }

        interval = ngx_current_msec - peer_shm->access_time;

        if (peer_shm->fast_check_count < peer->policy->data.fall) {
            peer_shm->fast_check_count += 1;
            interval = (peer->policy->data.check_interval << 4) + 1;
        }

        ngx_log_debug4(NGX_LOG_DEBUG_STREAM, event->log, 0,
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
            ngx_log_debug2(NGX_LOG_DEBUG_STREAM, event->log, 0,
                "on start check handler: start check peer name addr:%V "
                "type:%ui",
                &peer->policy->peer_name, peer->policy->data.type);
            ngx_stream_health_detect_connect_handler(event);
            return;
        }
        ngx_shmtx_unlock(&shpool->mutex);
    }
}

static ngx_int_t
ngx_stream_health_detect_add_timer(ngx_rbtree_node_t *node)
{
    ngx_msec_int_t delay;
    ngx_health_detect_peer_t *peer;

    peer = (ngx_health_detect_peer_t *) (&node->color);

    peer->check_ev.handler = ngx_stream_health_detect_start_check_handler;
    peer->check_ev.log = ngx_cycle->log;
    peer->check_ev.data = node;
    peer->check_ev.timer_set = 0;

    peer->check_timeout_ev.handler = ngx_stream_health_detect_timeout_handler;
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
                ? 1000
                : peer->policy->data.check_interval;
    ngx_add_timer(&peer->check_ev, ngx_random() % delay);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0,
        "add timer for peer name(%V)", &peer->policy->peer_name);
    return NGX_OK;
}

ngx_health_detect_default_detect_policy_t *
ngx_stream_health_detect_get_default_detect_policy(ngx_uint_t type)
{
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

ngx_health_detect_detect_policy_t *
ngx_stream_health_detect_construct_policy(ngx_pool_t *temp_pool,
    ngx_stream_upstream_srv_conf_t *us, ngx_str_t *server,
    ngx_addr_t *peer_addr)
{
    ngx_health_detect_detect_policy_t *policy;
    ngx_health_detect_default_detect_policy_t *default_policy;
    uint32_t hash;
    ngx_stream_health_detect_srv_conf_t *hdscf;

    hdscf =
        ngx_stream_conf_upstream_srv_conf(us, ngx_stream_health_detect_module);

    policy = ngx_pcalloc(temp_pool, sizeof(ngx_health_detect_detect_policy_t));

    policy->peer_name.len =
        us->host.len + server->len + peer_addr->name.len + 2;
    policy->peer_name.data = ngx_pcalloc(temp_pool, policy->peer_name.len);
    if (policy->peer_name.data == NULL) {
        return NULL;
    }
    ngx_snprintf(policy->peer_name.data, policy->peer_name.len, "%V-%V-%V",
        &us->host, server, &peer_addr->name);

    policy->peer_addr.sockaddr = ngx_pcalloc(temp_pool, peer_addr->socklen);
    if (policy->peer_addr.sockaddr == NULL) {
        return NULL;
    }
    memcpy(policy->peer_addr.sockaddr, peer_addr->sockaddr, peer_addr->socklen);
    policy->peer_addr.socklen = peer_addr->socklen;

    u_char *q = ngx_pnalloc(temp_pool, NGX_SOCKADDR_STRLEN);
    if (q == NULL) {
        return NULL;
    }

    size_t len = ngx_sock_ntop(
        peer_addr->sockaddr, peer_addr->socklen, q, NGX_SOCKADDR_STRLEN, 1);
    policy->peer_addr.name.len = len;
    policy->peer_addr.name.data = q;

    policy->send_content.len = hdscf->send_content.len;
    policy->send_content.data = ngx_pstrdup(temp_pool, &hdscf->send_content);
    if (policy->send_content.data == NULL) {
        return NULL;
    }

    policy->data = hdscf->data;

    default_policy =
        ngx_stream_health_detect_get_default_detect_policy(policy->data.type);
    if (default_policy == NULL) {
        return NULL;
    }

    if (policy->data.alert_method == NGX_CONF_UNSET_UINT) {
        policy->data.alert_method =
            ngx_health_detect_get_policy_alert_method_from_string(
                &default_policy->alert_method);
    }
    if (policy->data.expect_response_status.http_status ==
        NGX_CONF_UNSET_UINT) {
        policy->data.expect_response_status.http_status =
            default_policy->expect_response_status;
    }
    if (policy->data.fall == NGX_CONF_UNSET_UINT) {
        policy->data.fall = default_policy->fall;
    }

    if (policy->data.rise == NGX_CONF_UNSET_UINT) {
        policy->data.rise = default_policy->rise;
    }

    if (policy->data.check_interval == NGX_CONF_UNSET_MSEC) {
        policy->data.check_interval = default_policy->check_interval;
    }

    if (policy->data.check_timeout == NGX_CONF_UNSET_MSEC) {
        policy->data.check_timeout = default_policy->check_timeout;
    }
    if (policy->data.need_keepalive == NGX_CONF_UNSET_UINT) {
        policy->data.need_keepalive = default_policy->need_keepalive;
    }

    if (policy->data.keepalive_time == NGX_CONF_UNSET_MSEC) {
        policy->data.keepalive_time = default_policy->keepalive_time;
    }

    policy->data.from_upstream = 1;

    ngx_crc32_init(hash);
    ngx_crc32_update(&hash, policy->peer_name.data, policy->peer_name.len);
    ngx_crc32_update(
        &hash, policy->peer_addr.name.data, policy->peer_addr.name.len);
    ngx_crc32_update(
        &hash, policy->send_content.data, policy->send_content.len);
    ngx_crc32_update(&hash, (u_char *) &policy->data, sizeof(policy->data));
    ngx_crc32_final(hash);

    policy->checksum = hash;

    return policy;
}

ngx_uint_t
ngx_stream_health_detect_upstream_add_peer(ngx_stream_upstream_srv_conf_t *us,
    ngx_str_t *server, ngx_addr_t *peer_addr)
{
    ngx_int_t rc;
    ngx_pool_t *temp_pool;
    ngx_health_detect_detect_policy_t *policy;
    ngx_stream_health_detect_srv_conf_t *hdscf;

    if (us->srv_conf == NULL) {
        return NGX_ERROR;
    }

    hdscf =
        ngx_stream_conf_upstream_srv_conf(us, ngx_stream_health_detect_module);

    if (hdscf->data.check_interval == NGX_CONF_UNSET_MSEC) {
        return NGX_ERROR;
    }

    temp_pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (temp_pool == NULL) {
        return NGX_ERROR;
    }

    policy = ngx_stream_health_detect_construct_policy(
        temp_pool, us, server, peer_addr);

    if (policy == NULL) {
        ngx_destroy_pool(temp_pool);
        return NGX_ERROR;
    }

    if (ngx_process == NGX_PROCESS_WORKER) {
        rc = ngx_stream_health_detect_add_or_update_node(policy);
    } else {
        rc = ngx_stream_health_detect_add_or_update_node_on_local(policy, 0);
    }

    if (rc == NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            "upstream add peer policy:peer_name(%V) type(%ui) peer_addr(%V)"
            "send_content(%V) "
            "alert_method(%ui) "
            "expect_response_status(%ui) "
            "check_interval(%ui) check_timeout(%ui) fall(%ui) rise(%ui) "
            "keepalive(%ui) keepalive_time(%ui) success",
            &policy->peer_name, policy->data.type, &policy->peer_addr.name,
            policy->send_content.len == 0
                ? &ngx_stream_health_detect_get_default_detect_policy(
                      policy->data.type)
                       ->default_send_content
                : &policy->send_content,

            policy->data.alert_method,
            policy->data.expect_response_status.http_status,
            policy->data.check_interval, policy->data.check_timeout,
            policy->data.fall, policy->data.rise, policy->data.need_keepalive,
            policy->data.keepalive_time);

    } else {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            "upstream add peer policy:peer_name(%V) type(%ui) peer_addr(%V) "
            "fail",
            &policy->peer_name, policy->data.type, &policy->peer_addr.name);
    }

    ngx_destroy_pool(temp_pool);

    return rc;
}

void
ngx_stream_health_detect_upstream_delete_peer(
    ngx_str_t *upstream_name, ngx_str_t *server_name, ngx_addr_t *peer_addr)
{
    ngx_pool_t *temp_pool;
    ngx_str_t full_name;

    temp_pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    full_name.len =
        upstream_name->len + server_name->len + peer_addr->name.len + 2;
    full_name.data = ngx_pcalloc(temp_pool, full_name.len);
    ngx_snprintf(full_name.data, full_name.len, "%V-%V-%V", upstream_name,
        server_name, &peer_addr->name);

    ngx_stream_health_detect_delete_node(&full_name);

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "upstream delete peer(%V)",
        &full_name);

    ngx_destroy_pool(temp_pool);
}

ngx_uint_t
ngx_stream_health_detect_upstream_check_peer_down(
    ngx_str_t *upstream_name, ngx_str_t *server_name, ngx_str_t *peer_addr_name)
{
    ngx_pool_t *temp_pool;
    ngx_str_t full_name;
    uint32_t hash;
    ngx_slab_pool_t *shpool;
    ngx_rbtree_node_t *node_shm;
    ngx_health_detect_peer_shm_t *peer_shm;
    ngx_uint_t rc;

   /* upstream server_name is empty when not use upstream block */
    if (server_name->len == 0) {
        return 0;
    }

    temp_pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    full_name.len =
        upstream_name->len + server_name->len + peer_addr_name->len + 2;
    full_name.data = ngx_pcalloc(temp_pool, full_name.len);

    full_name.len = ngx_snprintf(full_name.data, full_name.len, "%V-%V-%V",
                        upstream_name, server_name, peer_addr_name) -
                    full_name.data;

    shpool = peers_manager_ctx->peers_shm->shpool;

    hash = ngx_crc32_short(full_name.data, full_name.len);

    ngx_shmtx_lock(&shpool->mutex);

    node_shm =
        ngx_stream_health_detect_peers_shm_rbtree_lookup(hash, &full_name);
    if (node_shm != NULL) {
        peer_shm = (ngx_health_detect_peer_shm_t *) &node_shm->color;
        rc = (peer_shm->status.latest_status == NGX_CHECK_STATUS_UP ? 0 : 1);
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            "check stream upstream peer(%V) down flag(%ui)", &full_name, rc);

    } else {
        rc = 0;
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            "check stream upstream peer(%V) not found, down flag(%ui)",
            &full_name, rc);
    }
    ngx_shmtx_unlock(&shpool->mutex);

    ngx_destroy_pool(temp_pool);

    return rc;
}

static ngx_int_t
ngx_stream_health_detect_sync_peers_to_peers_shm(ngx_uint_t reuse_old_data)
{
    ngx_health_detect_peers_shm_t *peers_shm;
    ngx_health_detect_peers_t *peers;
    ngx_rbtree_node_t *node, *root, *sentinel;
    ngx_health_detect_peer_shm_t *peer_shm;
    ngx_rbtree_node_t *node_shm, *root_shm, *sentinel_shm;
    ngx_health_detect_peer_t *peer;
    ngx_rbtree_node_t *delete_node[DEFAULT_PEER_NUMS_MAX_VALUE];
    ngx_uint_t i, delete_count;

    peers_shm = peers_manager_ctx->peers_shm;
    peers = peers_manager_ctx->peers;

    if (reuse_old_data) {
        delete_count = 0;
        root_shm = peers_shm->rbtree.root;
        sentinel_shm = peers_shm->rbtree.sentinel;
        if (root_shm != sentinel_shm) {
            for (node_shm = ngx_rbtree_min(root_shm, sentinel_shm); node_shm;
                 node_shm = ngx_rbtree_next(&peers_shm->rbtree, node_shm)) {
                peer_shm = (ngx_health_detect_peer_shm_t *) (&node_shm->color);

                node = ngx_stream_health_detect_peers_rbtree_lookup(
                    node_shm->key, &peer_shm->policy.peer_name);
                if (node != NULL) {
                    peer = (ngx_health_detect_peer_t *) &node->color;
                    if (peer->policy->checksum == peer_shm->policy.checksum) {
                        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                            "peer_shm name(%V) same as peer name on peers, "
                            "needn't delete when sync peers to peers_shm",
                            &peer_shm->policy.peer_name);
                        continue;
                    }
                }

                delete_node[delete_count] = node_shm;
                delete_count++;

                ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                    "peer_shm "
                    "name(%V) not exits on peers, need delete when sync "
                    "peers to peers_shm",
                    &peer_shm->policy.peer_name);
            }
        }

        for (i = 0; i < delete_count; i++) {
            peer_shm = (ngx_health_detect_peer_shm_t *) &delete_node[i]->color;
            if (peer_shm->policy.data.from_upstream) {
                /* because the free action occurs when reload, execute only
                 * once, so force free this node even if it policy data
                 * from_upstream*/
                peer_shm->ref = 1;
            }
            ngx_stream_health_detect_shm_free_node(delete_node[i]);
        }
    }

    sentinel = peers->rbtree.sentinel;
    root = peers->rbtree.root;
    if (root != sentinel) {
        for (node = ngx_rbtree_min(root, sentinel); node;
             node = ngx_rbtree_next(&peers->rbtree, node)) {
            peer = (ngx_health_detect_peer_t *) (&node->color);
            ngx_stream_health_detect_add_or_update_node_on_shm(peer->policy);
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_stream_health_detect_check_init_shm_zone(
    ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t *shpool;
    ngx_health_detect_peers_shm_t *peers_shm, *opeers_shm;
    size_t len;

    if (data != NULL) {
        shm_zone->data = data;

        if (peers_manager_ctx == NULL) {
            return NGX_OK;
        }

        opeers_shm = data;
        peers_manager_ctx->peers_shm = opeers_shm;
        peers_manager_ctx->peers_shm->shpool = opeers_shm->shpool;

        if (opeers_shm->checksum == peers_manager_ctx->peers->checksum) {
            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                "peers checksum equal to peers_shm checksum, "
                "use data directly");
        } else {
            ngx_stream_health_detect_sync_peers_to_peers_shm(1);
        }

        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    peers_shm = ngx_slab_calloc(shpool, sizeof(ngx_health_detect_peers_shm_t));
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
    peers_shm->max_number = DEFAULT_PEER_NUMS_MAX_VALUE;
    ;
    peers_shm->checksum = 0;
    ngx_rbtree_init(&peers_shm->rbtree, &peers_shm->sentinel,
        ngx_stream_health_detect_peer_shm_rbtree_insert_value);

    peers_manager_ctx->peers_shm = peers_shm;
    peers_manager_ctx->peers_shm->shpool = shpool;

    shm_zone->data = peers_manager_ctx->peers_shm;

    ngx_stream_health_detect_sync_peers_to_peers_shm(0);

    return NGX_OK;

failure:
    ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
        "ngx stream health detect: init shm zone error");

    return NGX_ERROR;
}

static char *
ngx_stream_health_detect_init_shm(
    ngx_conf_t *cf, void *conf, ngx_str_t *zone_name, ngx_int_t size)
{
    ngx_shm_zone_t *shm_zone;

    shm_zone = ngx_shared_memory_add(
        cf, zone_name, size, &ngx_stream_health_detect_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_stream_health_detect_check_init_shm_zone;

    return NGX_CONF_OK;
}

static void
ngx_stream_health_detect_sync_peers_shm_to_peers()
{
    ngx_rbtree_node_t *node_shm, *sentinel_shm, *root_shm;
    ngx_slab_pool_t *shpool;
    ngx_health_detect_peers_shm_t *peers_shm;
    ngx_health_detect_peer_shm_t *peer_shm;
    ngx_str_t *peer_name;
    ngx_rbtree_node_t *node;

    if (ngx_stream_health_detect_need_exit()) {
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0,
        "reload with start on %P", 0, ngx_pid);

    peers_shm = peers_manager_ctx->peers_shm;
    shpool = peers_shm->shpool;

    ngx_shmtx_lock(&shpool->mutex);

    sentinel_shm = peers_shm->rbtree.sentinel;
    root_shm = peers_shm->rbtree.root;
    shpool = peers_shm->shpool;
    if (root_shm != sentinel_shm) {
        for (node_shm = ngx_rbtree_min(root_shm, sentinel_shm); node_shm;
             node_shm = ngx_rbtree_next(&peers_shm->rbtree, node_shm)) {
            peer_shm = (ngx_health_detect_peer_shm_t *) (&node_shm->color);

            peer_name = &peer_shm->policy.peer_name;
            node = ngx_stream_health_detect_peers_rbtree_lookup(
                node_shm->key, peer_name);
            if (node == NULL) {
                ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0,
                    "on reload peer: reload peer name(%V) to peers_shm on "
                    "process(%P)",
                    peer_name, ngx_pid);
                ngx_stream_health_detect_add_or_update_node_on_local(
                    &peer_shm->policy, 1);
            }
        }
    }

    ngx_shmtx_unlock(&shpool->mutex);
}

static void
ngx_stream_health_detect_add_reload_shm_timer_handler(ngx_event_t *event)
{
    if (ngx_stream_health_detect_need_exit()) {
        return;
    }

    ngx_stream_health_detect_sync_peers_shm_to_peers();
    ngx_add_timer(event, 3000);
}

static ngx_int_t
ngx_stream_health_detect_add_reload_shm_timer(ngx_cycle_t *cycle)
{
    ngx_msec_int_t delay;
    ngx_event_t *reload_timer_ev;

    reload_timer_ev = &peers_manager_ctx->reload_timer_ev;
    reload_timer_ev->handler =
        ngx_stream_health_detect_add_reload_shm_timer_handler;
    reload_timer_ev->log = cycle->log;
    reload_timer_ev->data = NULL;
    reload_timer_ev->timer_set = 0;

    delay = ngx_random() % 1000;
    ngx_add_timer(reload_timer_ev, delay);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0,
        "add reload shared memory timer");
    return NGX_OK;
}

static ngx_int_t
ngx_stream_health_detect_add_peers_times(ngx_cycle_t *cycle)
{
    ngx_rbtree_node_t *node;
    ngx_rbtree_node_t *root, *sentinel;

    sentinel = peers_manager_ctx->peers->rbtree.sentinel;
    root = peers_manager_ctx->peers->rbtree.root;
    if (root != sentinel) {
        for (node = ngx_rbtree_min(root, sentinel); node;
             node = ngx_rbtree_next(&peers_manager_ctx->peers->rbtree, node)) {
            ngx_stream_health_detect_add_timer(node);
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_stream_health_detect_init_process(ngx_cycle_t *cycle)
{
    ngx_stream_health_detect_main_conf_t *hdmcf;
    ngx_int_t rc;

    if (ngx_process != NGX_PROCESS_WORKER) {
        return NGX_OK;
    }

    hdmcf = ngx_stream_cycle_get_module_main_conf(
        cycle, ngx_stream_health_detect_module);
    if (hdmcf == NULL) {
        return NGX_OK;
    }

    rc = ngx_stream_health_detect_add_peers_times(cycle);
    if (rc != NGX_OK) {
        return rc;
    }
    return ngx_stream_health_detect_add_reload_shm_timer(cycle);
}
