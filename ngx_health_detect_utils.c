#include "ngx_health_detect_utils.h"

#include "ngx_health_detect_common.h"
ngx_int_t
ngx_http_health_detect_http_init(ngx_health_detect_peer_t *peer)
{
    ngx_http_check_data_ctx_t *ctx;

    ctx = peer->check_data;

    if (peer->policy->send_content.len == 0) {
        ctx->send.start = ctx->send.pos =
            (u_char *) peer->default_policy->default_send_content.data;
        ctx->send.end = ctx->send.last =
            ctx->send.start + peer->default_policy->default_send_content.len;

    } else {
        ctx->send.start = ctx->send.pos =
            (u_char *) peer->policy->send_content.data;
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
ngx_http_health_detect_parse_status_line(
    ngx_http_check_data_ctx_t *ctx, ngx_buf_t *b, ngx_http_status_t *status)
{
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

ngx_int_t
ngx_http_health_detect_http_parse(ngx_health_detect_peer_t *peer)
{
    ngx_int_t rc;
    ngx_uint_t code, code_n;
    ngx_http_check_data_ctx_t *ctx;

    ctx = peer->check_data;

    if ((ctx->recv.last - ctx->recv.pos) > 0) {
        rc = ngx_http_health_detect_parse_status_line(
            ctx, &ctx->recv, &ctx->status);
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

void
ngx_http_health_detect_http_reinit(ngx_health_detect_peer_t *peer)
{
    ngx_http_check_data_ctx_t *ctx;

    ctx = peer->check_data;

    ctx->send.pos = ctx->send.start;
    ctx->send.last = ctx->send.end;

    ctx->recv.pos = ctx->recv.last = ctx->recv.start;

    ctx->state = 0;

    ngx_memzero(&ctx->status, sizeof(ngx_http_status_t));
}

ngx_int_t
ngx_http_health_detect_ssl_hello_init(ngx_health_detect_peer_t *peer)
{
    ngx_http_check_data_ctx_t *ctx;

    ctx = peer->check_data;

    if (peer->policy->send_content.len == 0) {
        ctx->send.start = ctx->send.pos =
            (u_char *) peer->default_policy->default_send_content.data;
        ctx->send.end = ctx->send.last =
            ctx->send.start + peer->default_policy->default_send_content.len;

    } else {
        ctx->send.start = ctx->send.pos =
            (u_char *) peer->policy->send_content.data;
        ctx->send.end = ctx->send.last =
            ctx->send.start + peer->policy->send_content.len;
    }

    ctx->recv.start = ctx->recv.pos = NULL;
    ctx->recv.end = ctx->recv.last = NULL;

    return NGX_OK;
}

ngx_int_t
ngx_http_health_detect_ssl_hello_parse(ngx_health_detect_peer_t *peer)
{
    size_t size;
    ngx_ssl_server_hello_t *resp;
    ngx_http_check_data_ctx_t *ctx;

    ctx = peer->check_data;

    size = ctx->recv.last - ctx->recv.pos;
    if (size < sizeof(ngx_ssl_server_hello_t)) {
        return NGX_AGAIN;
    }

    resp = (ngx_ssl_server_hello_t *) ctx->recv.pos;

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
        "http check ssl_parse, type: %xd, version: %xd.%xd, "
        "length: %xd, handshanke_type: %xd, hello_version: %xd.%xd",
        resp->msg_type, resp->version.major, resp->version.minor,
        ntohs(resp->length), resp->handshake_type, resp->hello_version.major,
        resp->hello_version.minor);

    if (resp->msg_type != NGX_SSL_HANDSHAKE) {
        return NGX_ERROR;
    }

    if (resp->handshake_type != NGX_SSL_SERVER_HELLO) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

void
ngx_http_health_detect_ssl_hello_reinit(ngx_health_detect_peer_t *peer)
{
    ngx_http_check_data_ctx_t *ctx;

    ctx = peer->check_data;

    ctx->send.pos = ctx->send.start;
    ctx->send.last = ctx->send.end;

    ctx->recv.pos = ctx->recv.last = ctx->recv.start;
}

ngx_int_t
ngx_http_health_detect_peek_one_byte(ngx_connection_t *c)
{
    char buf[1];
    ngx_int_t n;
    ngx_err_t err;

    n = recv(c->fd, buf, 1, MSG_PEEK);
    err = ngx_socket_errno;

    ngx_log_error(
        NGX_LOG_DEBUG, c->log, err, "http check recv(): %i, fd: %d", n, c->fd);
    if (n == 1 || (n == -1 && err == NGX_EAGAIN)) {
        return NGX_OK;
    } else {
        return NGX_ERROR;
    }
}
