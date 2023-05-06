#include "ngx_health_detect_common.h"

ngx_int_t
ngx_health_detect_check_fall_rise_is_valid(ngx_msec_int_t count)
{
    if (count < PEER_CHECK_FALL_RISE_MIN_VALUE ||
        count > PEER_CHECK_FALL_RISE_MAX_VALUE) {
        return 0;
    }
    return 1;
}

ngx_int_t
ngx_health_detect_check_interval_is_valid(ngx_msec_int_t check_interval)
{
    if (check_interval < PEER_CHECK_INTERVAL_MIN_VALUE ||
        check_interval > PEER_CHECK_INTERVAL_MAX_VALUE) {
        return 0;
    }
    return 1;
}

ngx_int_t
ngx_health_detect_check_timeout_is_valid(ngx_msec_int_t check_timeout)
{
    if (check_timeout < PEER_CHECK_TIMEOUT_MIN_VALUE ||
        check_timeout > PEER_CHECK_TIMEOUT_MAX_VALUE) {
        return 0;
    }
    return 1;
}

ngx_int_t
ngx_health_detect_check_keepalive_time_is_valid(ngx_msec_int_t keepalive_time)
{
    if (keepalive_time < PEER_CHECK_KEEPALIVE_TIME_MIN_VALUE ||
        keepalive_time > PEER_CHECK_KEEPALIVE_TIME_MAX_VALUE) {
        return 0;
    }
    return 1;
}

ngx_uint_t
ngx_health_detect_get_policy_alert_method_from_string(ngx_str_t *alert_method)
{
    if ((alert_method->len == sizeof("log") - 1) &&
        (ngx_strncasecmp(
             alert_method->data, (u_char *) "log", alert_method->len) == 0)) {
        return NGX_HTTP_ALERT_METHOD_LOG;
    } else if ((alert_method->len == sizeof("syslog") - 1) &&
               (ngx_strncasecmp(alert_method->data, (u_char *) "syslog",
                    alert_method->len) == 0)) {
        return NGX_HTTP_ALERT_METHOD_SYSLOG;
    } else {
        return 0;
    }
}

char *
ngx_health_detect_api_get_policy_type_to_string(ngx_uint_t type)
{
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

ngx_uint_t
ngx_health_detect_get_policy_type_from_string(ngx_str_t *type)
{
    if ((type->len == sizeof("tcp") - 1) &&
        (ngx_strncasecmp(type->data, (u_char *) "tcp", type->len) == 0)) {
        return NGX_HTTP_CHECK_TCP;
    } else if ((type->len == sizeof("http") - 1) &&
               (ngx_strncasecmp(type->data, (u_char *) "http", type->len) ==
                   0)) {
        return NGX_HTTP_CHECK_HTTP;
    } else if ((type->len == sizeof("https") - 1) &&
               (ngx_strncasecmp(type->data, (u_char *) "https", type->len) ==
                   0)) {
        return NGX_HTTP_CHECK_SSL_HELLO;
    } else {
        return 0;
    }
}

static ngx_int_t
ngx_parse_addr_on_slab_pool_locked(
    ngx_slab_pool_t *pool, ngx_addr_t *addr, u_char *text, size_t len)
{
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

    addr->sockaddr->sa_family = (u_char) family;
    addr->socklen = len;
    switch (family) {
#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) addr->sockaddr;
            ngx_memcpy(sin6->sin6_addr.s6_addr, inaddr6.s6_addr, 16);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) addr->sockaddr;
            sin->sin_addr.s_addr = inaddr;
            break;
    }

    return NGX_OK;
}

ngx_int_t
ngx_parse_addr_port_on_slab_pool_locked(
    ngx_slab_pool_t *pool, ngx_addr_t *addr, u_char *text, size_t len)
{
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

    ngx_inet_set_port(addr->sockaddr, (in_port_t) port);

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