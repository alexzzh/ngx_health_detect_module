#ifndef _NGX_STREAM_HEALTH_DETECT_MODELE_H_INCLUDED_
#define _NGX_STREAM_HEALTH_DETECT_MODELE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

ngx_uint_t ngx_stream_health_detect_upstream_add_peer(
    ngx_stream_upstream_srv_conf_t *us, ngx_str_t *server,
    ngx_addr_t *peer_addr);

void ngx_stream_health_detect_upstream_delete_peer(
    ngx_str_t *upstream_name, ngx_str_t *server_name, ngx_addr_t *peer_addr);
ngx_uint_t ngx_stream_health_detect_upstream_check_peer_down(
    ngx_str_t *upstream_name, ngx_str_t *server_name,
    ngx_str_t *peer_addr_name);

#endif  //_NGX_STREAM_HEALTH_DETECT_MODELE_H_INCLUDED_