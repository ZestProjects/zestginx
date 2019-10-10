
/*
 * Copyright (C) Cloudflare, Inc.
 */


#ifndef _NGX_HTTP_V3_MODULE_H_INCLUDED_
#define _NGX_HTTP_V3_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <quiche.h>


typedef struct {
    ngx_quic_t                      quic;

    quiche_h3_config                *http3;

    ngx_msec_t                      idle_timeout;
    size_t                          max_data;
    size_t                          max_stream_data;
    ngx_uint_t                      max_requests;
    ngx_uint_t                      max_header_size;
    ngx_uint_t                      concurrent_streams;
} ngx_http_v3_srv_conf_t;


extern ngx_module_t  ngx_http_v3_module;


#endif /* _NGX_HTTP_V3_MODULE_H_INCLUDED_ */
