#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "cJSON.h"
#include "ngx_health_detect_common.h"

#define NGX_CHECK_HTTP_2XX 0x0002
#define NGX_CHECK_HTTP_3XX 0x0004
#define NGX_CHECK_HTTP_4XX 0x0008
#define NGX_CHECK_HTTP_5XX 0x0010
#define NGX_CHECK_HTTP_ERR 0x8000

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
#define NGX_PRASE_REQ_KEEPALIVE_NOT_BOOL -13
#define NGX_PRASE_REQ_INVALID_KEEPALIVE_TIME -14
#define NGX_PRASE_REQ_DEFALU_DOWN_NOT_BOOL -15

#define ADD_PEER 1
#define UPDATE_PEER 2
#define DELETE_PEER 3
#define DELETE_ALL_PEERS 4
#define CHECK_ONE_PEER_STATUS 5
#define CHECK_ALL_PEERS_STATUS 6

#define NGX_HEALTH_DETECT_API_ON_HTTP 0x0002
#define NGX_HEALTH_DETECT_API_ON_TCP 0x0004

//-------------------- http -------------------------
extern ngx_health_detect_peers_manager_t *http_peers_manager_ctx;

ngx_rbtree_node_t *ngx_http_health_detect_peers_shm_rbtree_lookup(
    uint32_t hash, ngx_str_t *key);
ngx_health_detect_default_detect_policy_t *
ngx_http_health_detect_get_default_detect_policy(ngx_uint_t type);
ngx_int_t ngx_http_health_detect_add_or_update_node(
    ngx_health_detect_detect_policy_t *policy);
ngx_int_t ngx_http_health_detect_delete_node(ngx_str_t *key);
ngx_int_t ngx_http_health_detect_delete_all_node();
ngx_uint_t ngx_http_health_detect_get_down_count();
//-------------------- stream -------------------------
extern ngx_health_detect_peers_manager_t *stream_peers_manager_ctx;

ngx_rbtree_node_t *ngx_stream_health_detect_peers_shm_rbtree_lookup(
    uint32_t hash, ngx_str_t *key);
ngx_health_detect_default_detect_policy_t *
ngx_stream_health_detect_get_default_detect_policy(ngx_uint_t type);
ngx_int_t ngx_stream_health_detect_add_or_update_node(
    ngx_health_detect_detect_policy_t *policy);
ngx_int_t ngx_stream_health_detect_delete_node(ngx_str_t *key);
ngx_int_t ngx_stream_health_detect_delete_all_node();
ngx_uint_t ngx_stream_health_detect_get_down_count();

typedef struct {
    ngx_uint_t check_only;
    ngx_uint_t stream_check_only;
    ngx_uint_t used_module;
} ngx_http_health_detect_api_loc_conf_t;

static ngx_int_t ngx_health_detect_api_handler(ngx_http_request_t *r);

static char *ngx_http_health_detect_api_mode(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_health_detect_api_mode(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_health_detect_api_create_loc_conf(ngx_conf_t *cf);
static char *ngx_health_detect_api_merge_loc_conf(
    ngx_conf_t *cf, void *parent, void *child);

typedef void (*ngx_health_detect_api_one_node_status_format_pt)(
    ngx_http_request_t *r, ngx_buf_t *b, ngx_health_detect_peer_shm_t *peer);
typedef void (*ngx_health_detect_api_all_node_status_format_pt)(
    ngx_http_request_t *r, ngx_buf_t *b, ngx_health_detect_peers_shm_t *peer,
    ngx_uint_t status_flag);

static void ngx_http_health_detect_all_status_json_format(ngx_http_request_t *r,
    ngx_buf_t *b, ngx_health_detect_peers_shm_t *peers, ngx_uint_t status_flag);
static void ngx_http_health_detect_one_status_json_format(
    ngx_http_request_t *r, ngx_buf_t *b, ngx_health_detect_peer_shm_t *peer);
static void ngx_http_health_detect_all_status_html_format(ngx_http_request_t *r,
    ngx_buf_t *b, ngx_health_detect_peers_shm_t *peers, ngx_uint_t status_flag);
static void ngx_http_health_detect_one_status_html_format(
    ngx_http_request_t *r, ngx_buf_t *b, ngx_health_detect_peer_shm_t *peer);

static ngx_int_t ngx_health_detect_add_or_update_node(
    ngx_http_request_t *r, void *data);
static ngx_int_t ngx_health_detect_delete_node(
    ngx_http_request_t *r, void *data);
static ngx_int_t ngx_health_detect_delete_all_node(
    ngx_http_request_t *r, void *data);

static ngx_int_t ngx_health_detect_check_node_status(
    ngx_http_request_t *r, void *data);
static ngx_int_t ngx_health_detect_check_all_node_status(
    ngx_http_request_t *r, void *data);

typedef struct {
    ngx_str_t format;
    ngx_str_t content_type;
    ngx_health_detect_api_one_node_status_format_pt one_node_output;
    ngx_health_detect_api_all_node_status_format_pt all_node_output;
} ngx_health_detect_api_format_ctx_t;

typedef struct {
    ngx_health_detect_api_format_ctx_t *format;
    ngx_flag_t flag;
} ngx_health_detect_api_status_ctx_t;

typedef ngx_int_t (*ngx_http_health_detect_api_command_pt)(
    ngx_health_detect_api_status_ctx_t *ctx, ngx_str_t *value);

typedef struct {
    ngx_str_t name;
    ngx_http_health_detect_api_command_pt handler;
} ngx_check_status_command_t;

static ngx_health_detect_api_format_ctx_t ngx_health_detect_status_formats[] = {
    {ngx_string("json"), ngx_string("application/json"),
        ngx_http_health_detect_one_status_json_format,
        ngx_http_health_detect_all_status_json_format},
    {ngx_string("html"), ngx_string("text/html"),
        ngx_http_health_detect_one_status_html_format,
        ngx_http_health_detect_all_status_html_format},
    {ngx_null_string, ngx_null_string, NULL, NULL}};

static ngx_health_detect_api_format_ctx_t *
ngx_http_get_check_status_format_conf(ngx_str_t *str)
{
    ngx_uint_t i;
    for (i = 0;; i++) {
        if (ngx_health_detect_status_formats[i].format.len == 0) {
            break;
        }
        if (str->len != ngx_health_detect_status_formats[i].format.len) {
            continue;
        }
        if (ngx_strncmp(str->data,
                ngx_health_detect_status_formats[i].format.data,
                str->len) == 0) {
            return &ngx_health_detect_status_formats[i];
        }
    }

    return NULL;
}

static ngx_int_t
ngx_upstream_check_status_command_format(
    ngx_health_detect_api_status_ctx_t *ctx, ngx_str_t *value)
{
    ctx->format = ngx_http_get_check_status_format_conf(value);
    if (ctx->format == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_upstream_check_status_command_status(
    ngx_health_detect_api_status_ctx_t *ctx, ngx_str_t *value)
{
    if (value->len == (sizeof("down") - 1) &&
        ngx_strncasecmp(value->data, (u_char *) "down", value->len) == 0) {
        ctx->flag |= NGX_CHECK_STATUS_DOWN;

    } else if (value->len == (sizeof("up") - 1) &&
               ngx_strncasecmp(value->data, (u_char *) "up", value->len) == 0) {
        ctx->flag |= NGX_CHECK_STATUS_UP;

    } else {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_check_status_command_t ngx_health_detect_api_status_commands[] = {

    {ngx_string("format"), ngx_upstream_check_status_command_format},

    {ngx_string("status"), ngx_upstream_check_status_command_status},

    {ngx_null_string, NULL}};

static ngx_conf_bitmask_t ngx_check_http_expect_alive_masks[] = {
    {ngx_string("http_2xx"), NGX_CHECK_HTTP_2XX},
    {ngx_string("http_3xx"), NGX_CHECK_HTTP_3XX},
    {ngx_string("http_4xx"), NGX_CHECK_HTTP_4XX},
    {ngx_string("http_5xx"), NGX_CHECK_HTTP_5XX},
    {ngx_string("http_err"), NGX_CHECK_HTTP_ERR}, {ngx_null_string, 0}};

static ngx_command_t ngx_http_health_detect_api_cmds[] = {
    {ngx_string("health_detect_dynamic_api"),
        NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1 |
            NGX_CONF_NOARGS,
        ngx_http_health_detect_api_mode, 0, 0, NULL},
    {ngx_string("stream_health_detect_dynamic_api"),
        NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1 |
            NGX_CONF_NOARGS,
        ngx_stream_health_detect_api_mode, 0, 0, NULL},
    ngx_null_command};

static ngx_http_module_t ngx_health_detect_api_modules_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_health_detect_api_create_loc_conf,
    ngx_health_detect_api_merge_loc_conf,
};

ngx_module_t ngx_health_detect_api_module = {NGX_MODULE_V1,
    &ngx_health_detect_api_modules_ctx, ngx_http_health_detect_api_cmds,
    NGX_HTTP_MODULE, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING};

static void *
ngx_health_detect_api_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_health_detect_api_loc_conf_t *apilcf;

    apilcf =
        ngx_pcalloc(cf->pool, sizeof(ngx_http_health_detect_api_loc_conf_t));
    if (apilcf == NULL) {
        return NULL;
    }

    apilcf->check_only = NGX_CONF_UNSET_UINT;
    apilcf->stream_check_only = NGX_CONF_UNSET_UINT;
    apilcf->used_module = NGX_CONF_UNSET_UINT;

    return apilcf;
}

static char *
ngx_health_detect_api_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_health_detect_api_loc_conf_t *prev = parent;
    ngx_http_health_detect_api_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->check_only, prev->check_only, 1);
    ngx_conf_merge_uint_value(
        conf->stream_check_only, prev->stream_check_only, 1);
    ngx_conf_merge_uint_value(conf->used_module, prev->used_module, 0);

    if ((conf->used_module & NGX_HEALTH_DETECT_API_ON_HTTP) &&
        (conf->used_module & NGX_HEALTH_DETECT_API_ON_TCP)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "both \"health_detect_dynamic_api\" and "
            "\"stream_health_detect_dynamic_api\" directive are "
            "not allowed to appear in the same location");
    }

    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
        "ngx health detect api module used_module(%ui)", conf->used_module);

    return NGX_CONF_OK;
}

static char *
ngx_http_health_detect_api_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_http_core_loc_conf_t *clcf;
    ngx_http_health_detect_api_loc_conf_t *apilcf;
    ngx_str_t s;

    value = cf->args->elts;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_health_detect_api_handler;

    if (cf->args->nelts == 2) {
        apilcf =
            ngx_http_conf_get_module_loc_conf(cf, ngx_health_detect_api_module);

        value = &value[1];

        if (ngx_strncmp(value->data, "check_only=", 11) != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid api_mode \"%V\", must be \"check_only=true\" "
                "or \"check_only=false\" ",
                value);
            return NGX_CONF_ERROR;
        }

        s.len = value->len - 11;
        s.data = value->data + 11;

        if (ngx_strcasecmp(s.data, (u_char *) "true") == 0) {
            apilcf->check_only = 1;
        } else if (ngx_strcasecmp(s.data, (u_char *) "false") == 0) {
            apilcf->check_only = 0;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid value \"%s\", "
                "it must be \"true\" or \"false\"",
                s.data);
            return NGX_CONF_ERROR;
        }
    }

    if (apilcf->used_module == NGX_CONF_UNSET_UINT) {
        apilcf->used_module = 0;
    }

    apilcf->used_module |= NGX_HEALTH_DETECT_API_ON_HTTP;

    return NGX_CONF_OK;
}

static char *
ngx_stream_health_detect_api_mode(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_http_core_loc_conf_t *clcf;
    ngx_http_health_detect_api_loc_conf_t *apilcf;
    ngx_str_t s;

    value = cf->args->elts;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_health_detect_api_handler;

    if (cf->args->nelts == 2) {
        apilcf =
            ngx_http_conf_get_module_loc_conf(cf, ngx_health_detect_api_module);

        value = &value[1];

        if (ngx_strncmp(value->data, "check_only=", 11) != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid api_mode \"%V\", must be \"check_only=true\" "
                "or \"check_only=false\" ",
                value);
            return NGX_CONF_ERROR;
        }

        s.len = value->len - 11;
        s.data = value->data + 11;

        if (ngx_strcasecmp(s.data, (u_char *) "true") == 0) {
            apilcf->stream_check_only = 1;
        } else if (ngx_strcasecmp(s.data, (u_char *) "false") == 0) {
            apilcf->stream_check_only = 0;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid value \"%s\", "
                "it must be \"true\" or \"false\"",
                s.data);
            return NGX_CONF_ERROR;
        }
    }

    if (apilcf->used_module == NGX_CONF_UNSET_UINT) {
        apilcf->used_module = 0;
    }

    apilcf->used_module |= NGX_HEALTH_DETECT_API_ON_TCP;
    return NGX_CONF_OK;
}

static void
ngx_health_detect_judge_cond_to_string(
    char *dst, ngx_uint_t expect_response_status)
{
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

static void
ngx_http_rbtree_traverse_all_status_json_format(ngx_rbtree_node_t *node_shm,
    ngx_rbtree_node_t *sentinel, ngx_buf_t *b, ngx_uint_t status_flag)
{
    ngx_health_detect_peer_shm_t *peer_shm;
    ngx_uint_t need_print;

    if (node_shm == sentinel) {
        return;
    }

    ngx_http_rbtree_traverse_all_status_json_format(
        node_shm->left, sentinel, b, status_flag);

    need_print = 1;
    peer_shm = (ngx_health_detect_peer_shm_t *) (&node_shm->color);
    if ((status_flag & NGX_CHECK_STATUS_DOWN) ||
        (status_flag & NGX_CHECK_STATUS_UP)) {
        if (status_flag != peer_shm->status.latest_status) {
            need_print = 0;
        }
    }

    if (need_print) {
        b->last = ngx_snprintf(b->last, b->end - b->last,
            "    {\"name\": \"%V\",\"addr\": \"%V\",\"access_time\": %V, "
            "\"status\": "
            "\"%s\"}, \n",
            &peer_shm->policy.peer_name, &peer_shm->policy.peer_addr.name,
            &peer_shm->status.latest_access_time,
            peer_shm->status.latest_status == NGX_CHECK_STATUS_UP ? "up"
                                                                  : "down");
    }

    ngx_http_rbtree_traverse_all_status_json_format(
        node_shm->right, sentinel, b, status_flag);
}

static void
ngx_http_health_detect_all_status_json_format(ngx_http_request_t *r,
    ngx_buf_t *b, ngx_health_detect_peers_shm_t *peers_shm,
    ngx_uint_t status_flag)
{
    ngx_rbtree_node_t *node_shm, *sentinel;
    ngx_uint_t down_count;
    ngx_http_health_detect_api_loc_conf_t *apicf;

    apicf = ngx_http_get_module_loc_conf(r, ngx_health_detect_api_module);

    node_shm = peers_shm->rbtree.root;
    sentinel = peers_shm->rbtree.sentinel;

    if (apicf->used_module & NGX_HEALTH_DETECT_API_ON_HTTP) {
        down_count = ngx_http_health_detect_get_down_count();
    } else {
        down_count = ngx_stream_health_detect_get_down_count();
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
        "{\n\"total\": %ui,\n \"up\": %ui,\n \"down\": %ui,"
        "\n \"max\": %ui,\n\"items\": [\n",
        peers_shm->number, peers_shm->number - down_count, down_count,
        peers_shm->max_number);

    ngx_http_rbtree_traverse_all_status_json_format(
        node_shm, sentinel, b, status_flag);

    b->last = ngx_snprintf(b->last, b->end - b->last, "  ]\n");
    b->last = ngx_snprintf(b->last, b->end - b->last, "}\n");
}

static void
ngx_http_health_detect_one_status_json_format(
    ngx_http_request_t *r, ngx_buf_t *b, ngx_health_detect_peer_shm_t *peer_shm)
{
    ngx_health_detect_one_peer_status *status;
    ngx_queue_t *q;
    char user_define_cond_str[80];
    ngx_str_t *send_content;
    ngx_http_health_detect_api_loc_conf_t *apicf;

    apicf = ngx_http_get_module_loc_conf(r, ngx_health_detect_api_module);

    ngx_memzero(user_define_cond_str, sizeof(user_define_cond_str));
    ngx_health_detect_judge_cond_to_string(user_define_cond_str,
        peer_shm->policy.data.expect_response_status.http_status);

    if (peer_shm->policy.send_content.len == 0) {
        if (apicf->used_module & NGX_HEALTH_DETECT_API_ON_HTTP) {
            send_content = &ngx_http_health_detect_get_default_detect_policy(
                peer_shm->policy.data.type)
                                ->default_send_content;
        } else {
            send_content = &ngx_stream_health_detect_get_default_detect_policy(
                peer_shm->policy.data.type)
                                ->default_send_content;
        }
    } else {
        send_content = &peer_shm->policy.send_content;
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
        "{"
        "\"peer_name\": \"%V\",\n"
        "  \"type\": \"%s\",\n"
        "  \"peer_addr\": \"%V\",\n"
        "  \"alert_method\": \"%s\",\n"
        "  \"expect_response_status\": \"%s\",\n"
        "  \"check_interval\": \"%ui\",\n"
        "  \"check_timeout\": \"%ui\",\n"
        "  \"need_keepalive\": \"%ui\",\n"
        "  \"keepalive_time\": \"%ui\",\n"
        "  \"rise\": \"%ui\",\n"
        "  \"fall\": \"%ui\",\n"
        "  \"send_content\": \"%V\",\n"
        "  \"access_time\": \"%V\",\n"
        "  \"latest_status\": \"%s\",\n"
        "  \"max_status_count\": \"%ui\",\n"
        "  \"history_status\": {\n"
        "    \"current_status_count\": \"%ui\",\n"
        "    \"items\": [\n",
        &peer_shm->policy.peer_name,
        ngx_health_detect_api_get_policy_type_to_string(
            peer_shm->policy.data.type),
        &peer_shm->policy.peer_addr.name,
        ngx_health_detect_api_get_policy_type_to_string(
            peer_shm->policy.data.alert_method),
        user_define_cond_str, peer_shm->policy.data.check_interval,
        peer_shm->policy.data.check_timeout,
        peer_shm->policy.data.need_keepalive,
        peer_shm->policy.data.keepalive_time, peer_shm->policy.data.rise,
        peer_shm->policy.data.fall, send_content,
        &peer_shm->status.latest_access_time,
        peer_shm->status.latest_status == NGX_CHECK_STATUS_UP ? "up" : "down",
        peer_shm->status.max_status_count,
        peer_shm->status.current_status_count);

    for (q = ngx_queue_head(&peer_shm->status.history_status);
         q != ngx_queue_sentinel(&peer_shm->status.history_status);
         q = ngx_queue_next(q)) {
        status = ngx_queue_data(q, ngx_health_detect_one_peer_status, link);
        b->last = ngx_snprintf(b->last, b->end - b->last,
            "    {\"access_time\": %V, \"status\": \"%s\",} \n",
            &status->access_time,
            status->status == NGX_CHECK_STATUS_UP ? "up" : "down");
    }

    b->last = ngx_snprintf(b->last, b->end - b->last, "  ]\n");

    b->last = ngx_snprintf(b->last, b->end - b->last, "}}\n");
}

static void
ngx_http_health_detect_one_status_html_format(
    ngx_http_request_t *r, ngx_buf_t *b, ngx_health_detect_peer_shm_t *peer_shm)
{
    ngx_health_detect_one_peer_status *status;
    ngx_queue_t *q;
    ngx_str_t *send_content;
    char user_define_cond_str[80];
    ngx_http_health_detect_api_loc_conf_t *apicf;

    apicf = ngx_http_get_module_loc_conf(r, ngx_health_detect_api_module);

    ngx_memzero(user_define_cond_str, sizeof(user_define_cond_str));
    ngx_health_detect_judge_cond_to_string(user_define_cond_str,
        peer_shm->policy.data.expect_response_status.http_status);

    if (peer_shm->policy.send_content.len == 0) {
        if (apicf->used_module & NGX_HEALTH_DETECT_API_ON_HTTP) {
            send_content = &ngx_http_health_detect_get_default_detect_policy(
                peer_shm->policy.data.type)
                                ->default_send_content;
        } else {
            send_content = &ngx_stream_health_detect_get_default_detect_policy(
                peer_shm->policy.data.type)
                                ->default_send_content;
        }
    } else {
        send_content = &peer_shm->policy.send_content;
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
        "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\n"
        "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
        "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"
        "<head>\n"
        "  <title>Nginx health detect status "
        "style=\"background-color:red\" </title>\n"
        "</head>\n"
        "<body>\n"
        "<h1>Nginx health detect status</h1>\n"
        "<h2>Peer_name : %V,  Type: %s,  Peer_addr: %V</h2>\n"
        "<table style=\"background-color:white\" cellspacing=\"0\" "
        "       cellpadding=\"3\" border=\"1\">\n"
        "  <tr bgcolor=\"#FFFF00\">\n"
        "    <th>alert_method</th>\n"
        "    <th>expect_response_status</th>\n"
        "    <th>check_interval</th>\n"
        "    <th>check_timeout</th>\n"
        "    <th>need_keepalive</th>\n"
        "    <th>keepalive_time</th>\n"
        "    <th>rise</th>\n"
        "    <th>fall</th>\n"
        "    <th>send_content</th>\n"
        "    <th>latest_access_time</th>\n"
        "    <th>latest_status</th>\n"
        "    <th>max_status_count</th>\n"
        "  </tr>\n",
        &peer_shm->policy.peer_name,
        ngx_health_detect_api_get_policy_type_to_string(
            peer_shm->policy.data.type),
        &peer_shm->policy.peer_addr.name);

    b->last = ngx_snprintf(b->last, b->end - b->last,
        "  <tr  bgcolor=\"#C0C0C0\">\n"
        "    <td>%s</td>\n"
        "    <td>%s</td>\n"
        "    <td>%ui</td>\n"
        "    <td>%ui</td>\n"
        "    <td>%ui</td>\n"
        "    <td>%ui</td>\n"
        "    <td>%ui</td>\n"
        "    <td>%ui</td>\n"
        "    <td>%V</td>\n"
        "    <td>%V</td>\n"
        "    <td>%s</td>\n"
        "    <td>%ui</td>\n"
        "  </tr>\n",
        ngx_health_detect_api_get_policy_type_to_string(
            peer_shm->policy.data.alert_method),
        user_define_cond_str, peer_shm->policy.data.check_interval,
        peer_shm->policy.data.check_timeout,
        peer_shm->policy.data.need_keepalive,
        peer_shm->policy.data.keepalive_time, peer_shm->policy.data.rise,
        peer_shm->policy.data.fall, send_content,
        &peer_shm->status.latest_access_time,
        peer_shm->status.latest_status == NGX_CHECK_STATUS_UP ? "up" : "down",
        peer_shm->status.max_status_count);

    b->last = ngx_snprintf(b->last, b->end - b->last, "</table>\n");

    b->last = ngx_snprintf(b->last, b->end - b->last,
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
        b->last = ngx_snprintf(b->last, b->end - b->last,
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

static void
ngx_http_rbtree_traverse_all_status_html_format(ngx_rbtree_node_t *node_shm,
    ngx_rbtree_node_t *sentinel, ngx_buf_t *b, ngx_uint_t status_flag)
{
    ngx_health_detect_peer_shm_t *peer_shm;
    ngx_uint_t need_print;

    if (node_shm == sentinel) {
        return;
    }

    ngx_http_rbtree_traverse_all_status_html_format(
        node_shm->left, sentinel, b, status_flag);

    need_print = 1;
    peer_shm = (ngx_health_detect_peer_shm_t *) (&node_shm->color);
    if ((status_flag & NGX_CHECK_STATUS_DOWN) ||
        (status_flag & NGX_CHECK_STATUS_UP)) {
        if (status_flag != peer_shm->status.latest_status) {
            need_print = 0;
        }
    }

    if (need_print) {
        b->last = ngx_snprintf(b->last, b->end - b->last,
            "  <tr  bgcolor=\"#C0C0C0\">\n"
            "<td>%V</td>\n"
            " <td>%V</td>\n"
            " <td>%V</td>\n"
            " <td>%s</td>\n"
            "  <tr>\n",
            &peer_shm->policy.peer_name, &peer_shm->policy.peer_addr.name,
            &peer_shm->status.latest_access_time,
            peer_shm->status.latest_status == NGX_CHECK_STATUS_UP ? "up"
                                                                  : "down");
    }

    ngx_http_rbtree_traverse_all_status_html_format(
        node_shm->right, sentinel, b, status_flag);
}

static void
ngx_http_health_detect_all_status_html_format(ngx_http_request_t *r,
    ngx_buf_t *b, ngx_health_detect_peers_shm_t *peers_shm,
    ngx_uint_t status_flag)
{
    ngx_rbtree_node_t *node_shm, *sentinel;
    ngx_uint_t down_count;
    ngx_http_health_detect_api_loc_conf_t *apicf;

    node_shm = peers_shm->rbtree.root;
    sentinel = peers_shm->rbtree.sentinel;

    apicf = ngx_http_get_module_loc_conf(r, ngx_health_detect_api_module);

    if (apicf->used_module & NGX_HEALTH_DETECT_API_ON_HTTP) {
        down_count = ngx_http_health_detect_get_down_count();
    } else {
        down_count = ngx_stream_health_detect_get_down_count();
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
        "<h2>Total: %ui, Up: %ui, Down: %ui, Max: %ui</h2>\n"
        "<table style=\"background-color:white\" cellspacing=\"0\" "
        "       cellpadding=\"3\" border=\"1\">\n"
        "  <tr bgcolor=\"#FFFF00\">\n"
        "    <td class=\"column\"\">name</td>\n"
        "    <td class=\"column\"\">addr</td>\n"
        "    <td class=\"column\"\">access_time</td>\n"
        "    <td class=\"column\"\">status</td>\n"
        "  </tr>\n",
        peers_shm->number, peers_shm->number - down_count, down_count,
        peers_shm->max_number);

    ngx_http_rbtree_traverse_all_status_html_format(
        node_shm, sentinel, b, status_flag);

    b->last = ngx_snprintf(b->last, b->end - b->last,
        "</table>\n"
        "</body>\n"
        "</html>\n");
}

static ngx_int_t
ngx_health_detect_add_or_update_node(ngx_http_request_t *r, void *data)
{
    ngx_int_t rc;
    ngx_http_health_detect_api_loc_conf_t *apicf;

    ngx_health_detect_detect_policy_t *policy = data;
    apicf = ngx_http_get_module_loc_conf(r, ngx_health_detect_api_module);

    if (apicf->used_module & NGX_HEALTH_DETECT_API_ON_HTTP) {
        rc = ngx_http_health_detect_add_or_update_node(policy);
    } else {
        rc = ngx_stream_health_detect_add_or_update_node(policy);
    }

    return rc;
}

static ngx_int_t
ngx_health_detect_delete_node(ngx_http_request_t *r, void *data)
{
    ngx_int_t rc;
    ngx_http_health_detect_api_loc_conf_t *apicf;

    ngx_str_t *key = data;
    apicf = ngx_http_get_module_loc_conf(r, ngx_health_detect_api_module);

    if (apicf->used_module & NGX_HEALTH_DETECT_API_ON_HTTP) {
        rc = ngx_http_health_detect_delete_node(key);
    } else {
        rc = ngx_stream_health_detect_delete_node(key);
    }

    return rc;
}

static ngx_int_t
ngx_health_detect_delete_all_node(ngx_http_request_t *r, void *data)
{
    ngx_int_t rc;
    ngx_http_health_detect_api_loc_conf_t *apicf;

    apicf = ngx_http_get_module_loc_conf(r, ngx_health_detect_api_module);
    if (apicf->used_module & NGX_HEALTH_DETECT_API_ON_HTTP) {
        rc = ngx_http_health_detect_delete_all_node();
    } else {
        rc = ngx_stream_health_detect_delete_all_node();
    }

    return rc;
}

static void
ngx_health_detect_api_parse_args(
    ngx_http_request_t *r, ngx_health_detect_api_status_ctx_t *ctx)
{
    ngx_str_t value;
    ngx_uint_t i;
    ngx_check_status_command_t *command;

    if (r->args.len == 0) {
        return;
    }

    for (i = 0;; i++) {
        command = &ngx_health_detect_api_status_commands[i];

        if (command->name.len == 0) {
            break;
        }

        if (ngx_http_arg(r, command->name.data, command->name.len, &value) ==
            NGX_OK) {
            if (command->handler(ctx, &value) != NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "args check, bad argument: \"%V\"", &value);
            }
        }
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "args check, flag: \"%ui\"", ctx->flag);
}

static ngx_buf_t *
ngx_health_detect_create_temp_response_buf(
    ngx_http_request_t *r, ngx_str_t *resp)
{
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

static ngx_int_t
ngx_health_detect_check_all_node_status(ngx_http_request_t *r, void *data)
{
    ngx_int_t rc;
    size_t buffer_size;
    ngx_buf_t *b;
    ngx_chain_t *out_chain;
    ngx_slab_pool_t *shpool;
    ngx_health_detect_api_status_ctx_t *ctx;
    ngx_http_health_detect_api_loc_conf_t *apicf;
    ngx_health_detect_peers_manager_t *peers_manager_ctx;

    apicf = ngx_http_get_module_loc_conf(r, ngx_health_detect_api_module);

    if (apicf->used_module & NGX_HEALTH_DETECT_API_ON_HTTP) {
        peers_manager_ctx = http_peers_manager_ctx;
    } else {
        peers_manager_ctx = stream_peers_manager_ctx;
    }

    shpool = peers_manager_ctx->peers_shm->shpool;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_health_detect_api_status_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_health_detect_api_parse_args(r, ctx);

    if (ctx->format == NULL) {
        ctx->format = &ngx_health_detect_status_formats[0];
    }
    r->headers_out.content_type = ctx->format->content_type;

    buffer_size = ngx_pagesize * 512;
    b = ngx_create_temp_buf(r->pool, buffer_size);

    ngx_shmtx_lock(&shpool->mutex);
    ctx->format->all_node_output(r, b, peers_manager_ctx->peers_shm, ctx->flag);
    ngx_shmtx_unlock(&shpool->mutex);

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

static ngx_int_t
ngx_health_detect_check_node_status(ngx_http_request_t *r, void *data)
{
    ngx_health_detect_peer_shm_t *peer_shm;
    ngx_int_t rc;
    size_t len, buffer_size;
    ngx_buf_t *b;
    ngx_chain_t *out_chain;
    ngx_rbtree_node_t *node_shm;
    ngx_slab_pool_t *shpool;
    uint32_t hash;
    ngx_str_t resp;
    ngx_health_detect_api_status_ctx_t *ctx;
    ngx_http_health_detect_api_loc_conf_t *apicf;

    apicf = ngx_http_get_module_loc_conf(r, ngx_health_detect_api_module);

    ngx_str_t *peer_name = data;
    if (apicf->used_module & NGX_HEALTH_DETECT_API_ON_HTTP) {
        shpool = http_peers_manager_ctx->peers_shm->shpool;
    } else {
        shpool = stream_peers_manager_ctx->peers_shm->shpool;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_health_detect_api_status_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_health_detect_api_parse_args(r, ctx);

    if (ctx->format == NULL) {
        ctx->format = &ngx_health_detect_status_formats[0];
    }
    r->headers_out.content_type = ctx->format->content_type;

    hash = ngx_crc32_short(peer_name->data, peer_name->len);

    ngx_shmtx_lock(&shpool->mutex);

    if (apicf->used_module & NGX_HEALTH_DETECT_API_ON_HTTP) {
        node_shm =
            ngx_http_health_detect_peers_shm_rbtree_lookup(hash, peer_name);
    } else {
        node_shm =
            ngx_stream_health_detect_peers_shm_rbtree_lookup(hash, peer_name);
    }

    if (node_shm != NULL) {
        peer_shm = (ngx_health_detect_peer_shm_t *) &node_shm->color;

        buffer_size = ngx_pagesize;
        b = ngx_create_temp_buf(r->pool, buffer_size);
        ctx->format->one_node_output(r, b, peer_shm);
        ngx_shmtx_unlock(&shpool->mutex);

        goto out;
    }

    ngx_shmtx_unlock(&shpool->mutex);
    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
        "on check status: can not find node on server: name:%V", peer_name);

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

static ngx_int_t
ngx_http_health_detect_check_url_name_arg(ngx_str_t *name)
{
    if (name->len > PEER_NAME_LEN_MAX_VALUE || name->len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }
    return NGX_HTTP_OK;
}

static ngx_int_t
ngx_http_health_detect_process_request(
    ngx_http_request_t *r, ngx_uint_t arg_cmd, ngx_str_t *resp)
{
    ngx_int_t rc;
    ngx_str_t arg_name;

    if (arg_cmd == CHECK_ONE_PEER_STATUS) {
        ngx_http_arg(r, (u_char *) "name", 4, &arg_name);
        return ngx_health_detect_check_node_status(r, &arg_name);
    } else if (arg_cmd == CHECK_ALL_PEERS_STATUS) {
        return ngx_health_detect_check_all_node_status(r, NULL);
    } else if (arg_cmd == DELETE_PEER) {
        ngx_http_arg(r, (u_char *) "name", 4, &arg_name);
        rc = ngx_health_detect_delete_node(r, &arg_name);
        if (rc != NGX_OK) {
            ngx_str_set(resp, "delete node error ");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        } else {
            ngx_str_set(resp, "delete node success ");
            rc = NGX_HTTP_OK;
        }
    } else if (arg_cmd == DELETE_ALL_PEERS) {
        rc = ngx_health_detect_delete_all_node(r, NULL);
        if (rc != NGX_OK) {
            ngx_str_set(resp, "delete all node error");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        } else {
            ngx_str_set(resp, "delete all node success");
            rc = NGX_HTTP_OK;
        }
    }

    return rc;
}

static ngx_health_detect_detect_policy_t *
ngx_health_detect_prase_request_body(
    ngx_http_request_t *r, ngx_str_t peer_name, ngx_int_t *prase_error)
{
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

    requst_body_json = cJSON_Parse((char *) buf->pos);
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
         * send_content    ngx_str_t  empty means use default value
         * alert_method    ngx_str_t  empty means use default value
         * expect_response_status  ngx_str_t  empty means use default value
         * interval        ngx_msec_int_t  empty means use default value
         * timeout         ngx_msec_int_t  empty means use default value
         * rise            ngx_uint_t  empty means use default value
         * fall            ngx_uint_t  empty means use default value
         * keepalive       ngx_uint_t  empty means use default value
         * keepalive_time  ngx_msec_int_t  empty means use default value
         * default_down    ngx_uint_t  empty means use default value
         * */

        policy =
            ngx_pcalloc(r->pool, sizeof(ngx_health_detect_detect_policy_t));

        policy->checksum = ngx_crc32_long(buf->pos, request_body_len);

        policy->peer_name.data = ngx_pstrdup(r->pool, &peer_name);
        if (policy->peer_name.data == NULL) {
            *prase_error = NGX_PRASE_REQ_ERR;
            goto fail;
        }
        policy->peer_name.len = peer_name.len;

        attr = cJSON_GetObjectItem(requst_body_json, "type");
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

            policy->data.type =
                ngx_health_detect_get_policy_type_from_string(&str);
            if (!policy->data.type) {
                *prase_error = NGX_PRASE_REQ_INVALID_PEER_TYPE;
                goto fail;
            }
        }

        default_policy = ngx_http_health_detect_get_default_detect_policy

            (policy->data.type);
        attr = cJSON_GetObjectItem(requst_body_json, (char *) "peer_addr");
        if (attr == NULL) {
            *prase_error = NGX_PRASE_REQ_PEER_ADDR_NOT_FOUND;
            goto fail;
        } else {
            data = attr->valuestring;
            len = ngx_strlen(data);
            *prase_error = ngx_parse_addr_port(
                r->pool, &policy->peer_addr, (u_char *) data, len);
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

        attr = cJSON_GetObjectItem(requst_body_json, (char *) "send_content");
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

        attr = cJSON_GetObjectItem(requst_body_json, (char *) "alert_method");
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
            cJSON_GetObjectItem(requst_body_json, (char *) "expect_response");
        if (attr == NULL) {
            policy->data.expect_response_status.http_status =
                default_policy->expect_response_status;
        } else {
            data = attr->valuestring;

            mask = 0;
            for (i = 0; ngx_check_http_expect_alive_masks[i].name.len != 0;
                 i++) {
                if (ngx_strcasestrn((u_char *) data,
                        (char *) ngx_check_http_expect_alive_masks[i].name.data,
                        ngx_check_http_expect_alive_masks[i].name.len - 1) !=
                    NULL) {
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
            if (!ngx_health_detect_check_fall_rise_is_valid(
                    policy->data.fall)) {
                *prase_error = NGX_PRASE_REQ_INVALID_CHECK_FALL_RISE_NUMBER;
                goto fail;
            }
        }

        attr = cJSON_GetObjectItem(requst_body_json, "rise");
        if (attr == NULL) {
            policy->data.rise = default_policy->rise;
        } else {
            policy->data.rise = attr->valueint;
            if (!ngx_health_detect_check_fall_rise_is_valid(
                    policy->data.rise)) {
                *prase_error = NGX_PRASE_REQ_INVALID_CHECK_FALL_RISE_NUMBER;
                goto fail;
            }
        }

        attr = cJSON_GetObjectItem(requst_body_json, "interval");
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

        attr = cJSON_GetObjectItem(requst_body_json, "timeout");
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

        attr = cJSON_GetObjectItem(requst_body_json, "keepalive");
        if (attr == NULL) {
            policy->data.need_keepalive = default_policy->need_keepalive;
        } else {
            policy->data.need_keepalive = attr->valueint;
            if (policy->data.need_keepalive != 0 &&
                policy->data.need_keepalive != 1) {
                *prase_error = NGX_PRASE_REQ_KEEPALIVE_NOT_BOOL;
                goto fail;
            }
        }

        attr = cJSON_GetObjectItem(requst_body_json, (char *) "keepalive");
        if (attr == NULL) {
            policy->data.need_keepalive = default_policy->need_keepalive;
        } else {
            data = attr->valuestring;
            if (ngx_strcasecmp((u_char *) data, (u_char *) "true") == 0) {
                policy->data.need_keepalive = 1;
            } else if (ngx_strcasecmp((u_char *) data, (u_char *) "false") ==
                       0) {
                policy->data.need_keepalive = 0;
            } else {
                *prase_error = NGX_PRASE_REQ_KEEPALIVE_NOT_BOOL;
                goto fail;
            }
        }

        attr = cJSON_GetObjectItem(requst_body_json, (char *) "default_down");
        if (attr == NULL) {
            policy->data.default_down = 0;
        } else {
            data = attr->valuestring;
            if (ngx_strcasecmp((u_char *) data, (u_char *) "true") == 0) {
                policy->data.default_down = 1;
            } else if (ngx_strcasecmp((u_char *) data, (u_char *) "false") ==
                       0) {
                policy->data.default_down = 0;
            } else {
                *prase_error = NGX_PRASE_REQ_DEFALU_DOWN_NOT_BOOL;
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

        policy->data.from_upstream = 0;
        *prase_error = NGX_PRASE_REQ_OK;

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "policy:peer_name(%V) type(%ui) peer_addr(%V)"
            "send_content(%V) "
            "alert_method(%ui) "
            "expect_response_status(%ui) "
            "check_interval(%ui) check_timeout(%ui) fall(%ui) rise(%ui)",
            &policy->peer_name, policy->data.type, &policy->peer_addr.name,
            policy->send_content.len == 0
                ? &ngx_http_health_detect_get_default_detect_policy(
                      policy->data.type)
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
ngx_http_health_detect_process_request_with_body(ngx_http_request_t *r)
{
    ngx_health_detect_detect_policy_t *policy;
    ngx_buf_t *b;
    ngx_chain_t *out;
    ngx_int_t rc, prase_error;
    ngx_str_t resp;
    ngx_str_t arg_name;

    ngx_http_arg(r, (u_char *) "name", 4, &arg_name);

    policy = ngx_health_detect_prase_request_body(r, arg_name, &prase_error);
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
                ngx_str_set(
                    &resp, "NGX_PRASE_REQ_INVALID_EXPECT_RESPONSE_STATUS");
                break;
            case NGX_PRASE_REQ_INVALID_CHECK_INTERVAL:
                ngx_str_set(&resp, "NGX_PRASE_REQ_INVALID_CHECK_INTERVAL");
                break;
            case NGX_PRASE_REQ_INVALID_CHECK_TIMEOUT:
                ngx_str_set(&resp, "NGX_PRASE_REQ_INVALID_CHECK_TIMEOUT");
                break;
            case NGX_PRASE_REQ_INVALID_CHECK_FALL_RISE_NUMBER:
                ngx_str_set(
                    &resp, "NGX_PRASE_REQ_INVALID_CHECK_FALL_RISE_NUMBER");
                break;
            case NGX_PRASE_REQ_KEEPALIVE_NOT_BOOL:
                ngx_str_set(&resp, "NGX_PRASE_REQ_NEED_KEEPALIVE_NOT_BOOL");
                break;
            case NGX_PRASE_REQ_DEFALU_DOWN_NOT_BOOL:
                ngx_str_set(&resp, "NGX_PRASE_REQ_DEFALU_DOWN_NOT_BOOL");
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

    rc = ngx_health_detect_add_or_update_node(r, policy);

    if (rc == NGX_ERROR) {
        ngx_str_set(&resp, "add or update node error");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    } else {
        ngx_str_set(&resp, "add or update node success");
        rc = NGX_HTTP_OK;
    }

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
static ngx_int_t
ngx_health_detect_api_check_url_valid(
    ngx_http_request_t *r, ngx_int_t *arg_cmd, ngx_str_t *resp)
{
    ngx_int_t rc;
    size_t len;
    u_char *p;
    ngx_str_t arg_cmd_s;
    ngx_str_t arg_name_s;

    rc = NGX_HTTP_BAD_REQUEST;

    p = (u_char *) ngx_strchr(r->uri.data, '/');

    if (p) {
        p = (u_char *) ngx_strchr(p + 1, '/');
        len = r->uri.len - (p - r->uri.data);
    }

    if (p && len >= sizeof("/control") - 1) {
        p = r->uri.data + r->uri.len - sizeof("/control") + 1;
        if (ngx_strncasecmp(p, (u_char *) "/control", sizeof("/control") - 1) ==
            0) {
            if (ngx_http_arg(r, (u_char *) "cmd", 3, &arg_cmd_s) == NGX_OK) {
                if (arg_cmd_s.len == 6 &&
                    ngx_strncmp(arg_cmd_s.data, "status", 6) == 0) {
                    if (ngx_http_arg(r, (u_char *) "name", 4, &arg_name_s) ==
                        NGX_OK) {
                        rc = ngx_http_health_detect_check_url_name_arg(
                            &arg_name_s);
                        if (rc != NGX_HTTP_OK) {
                            ngx_str_set(resp,
                                "check node status error: node arg invalid ");
                            goto out;
                        }
                        *arg_cmd = CHECK_ONE_PEER_STATUS;
                    } else {
                        ngx_str_set(resp,
                            "check node status error: not found node arg ");
                        goto out;
                    }
                } else if (arg_cmd_s.len == 10 &&
                           ngx_strncmp(arg_cmd_s.data, "status_all", 10) == 0) {
                    *arg_cmd = CHECK_ALL_PEERS_STATUS;
                } else if (arg_cmd_s.len == 6 &&
                           ngx_strncmp(arg_cmd_s.data, "delete", 6) == 0) {
                    if (ngx_http_arg(r, (u_char *) "name", 4, &arg_name_s) ==
                        NGX_OK) {
                        rc = ngx_http_health_detect_check_url_name_arg(
                            &arg_name_s);
                        if (rc != NGX_HTTP_OK) {
                            ngx_str_set(
                                resp, "delete node error: node arg invalid ");
                            goto out;
                        }
                        *arg_cmd = DELETE_PEER;
                    } else {
                        ngx_str_set(
                            resp, "delete node error: not found node name ");
                        goto out;
                    }
                } else if (arg_cmd_s.len == 10 &&
                           ngx_strncmp(arg_cmd_s.data, "delete_all", 10) == 0) {
                    *arg_cmd = DELETE_ALL_PEERS;
                } else if (arg_cmd_s.len == 3 &&
                           ngx_strncmp(arg_cmd_s.data, "add", 3) == 0) {
                    if (ngx_http_arg(r, (u_char *) "name", 4, &arg_name_s) ==
                        NGX_OK) {
                        rc = ngx_http_health_detect_check_url_name_arg(
                            &arg_name_s);
                        if (rc != NGX_HTTP_OK) {
                            ngx_str_set(resp,
                                "add or update node error: node arg invalid ");
                            goto out;
                        }
                        *arg_cmd = ADD_PEER;
                    }
                } else if (arg_cmd_s.len == 6 &&
                           ngx_strncmp(arg_cmd_s.data, "update", 6) == 0) {
                    if (ngx_http_arg(r, (u_char *) "name", 4, &arg_name_s) ==
                        NGX_OK) {
                        rc = ngx_http_health_detect_check_url_name_arg(
                            &arg_name_s);
                        if (rc != NGX_HTTP_OK) {
                            ngx_str_set(resp,
                                "add or update node error: node arg invalid ");
                            goto out;
                        }
                        *arg_cmd = UPDATE_PEER;
                    }
                } else {
                    ngx_str_set(resp,
                        "cmd arg invalid: should be "
                        "status|status_all|delete|delete_all|add|update ");
                    goto out;
                }
            } else {
                ngx_str_set(resp, "not found cmd arg");
                goto out;
            }
        } else {
            ngx_str_set(resp, "url should include \"/control\" in the end");
            goto out;
        }
    } else {
        ngx_str_set(resp, "url len less than \"/control\"");
        goto out;
    }

    rc = NGX_HTTP_OK;

out:
    return rc;
}

static ngx_int_t
ngx_health_detect_api_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_http_health_detect_api_loc_conf_t *apicf;
    ngx_int_t arg_cmd;
    ngx_str_t resp;
    ngx_buf_t *b;
    ngx_chain_t *out;

    apicf = ngx_http_get_module_loc_conf(r, ngx_health_detect_api_module);

    if (apicf->used_module & NGX_HEALTH_DETECT_API_ON_HTTP) {
        if (apicf->check_only) {
            if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
                return NGX_HTTP_NOT_ALLOWED;
            }
        }
    } else {
        if (apicf->stream_check_only) {
            if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
                return NGX_HTTP_NOT_ALLOWED;
            }
        }
    }

    rc = ngx_health_detect_api_check_url_valid(r, &arg_cmd, &resp);
    if (rc != NGX_HTTP_OK) {
        goto out;
    }

    if (apicf->used_module & NGX_HEALTH_DETECT_API_ON_HTTP) {
        if (apicf->check_only) {
            if (arg_cmd != CHECK_ONE_PEER_STATUS &&
                arg_cmd != CHECK_ALL_PEERS_STATUS) {
                return NGX_HTTP_NOT_ALLOWED;
            }
        }
    } else {
        if (apicf->stream_check_only) {
            if (arg_cmd != CHECK_ONE_PEER_STATUS &&
                arg_cmd != CHECK_ALL_PEERS_STATUS) {
                return NGX_HTTP_NOT_ALLOWED;
            }
        }
    }

    if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD ||
        r->method == NGX_HTTP_DELETE) {
        rc = ngx_http_discard_request_body(r);
        if (rc != NGX_OK) {
            return rc;
        }

        rc = ngx_http_health_detect_process_request(r, arg_cmd, &resp);
        if (arg_cmd == CHECK_ONE_PEER_STATUS ||
            arg_cmd == CHECK_ALL_PEERS_STATUS) {
            return rc;
        }
        goto out;
    }

    rc = ngx_http_read_client_request_body(
        r, ngx_http_health_detect_process_request_with_body);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;

out:
    b = ngx_health_detect_create_temp_response_buf(r, &resp);

    r->headers_out.status = rc;
    r->headers_out.content_length_n = b->last - b->pos;

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