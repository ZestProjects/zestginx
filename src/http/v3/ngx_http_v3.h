
/*
 * Copyright (C) Cloudflare, Inc.
 */


#ifndef _NGX_HTTP_V3_H_INCLUDED_
#define _NGX_HTTP_V3_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_v3_module.h>


#define NGX_HTTP_V3_ALPN_ADVERTISE       "\x05h3-18"


typedef struct ngx_http_v3_connection_s   ngx_http_v3_connection_t;


struct ngx_http_v3_connection_s {
    quiche_h3_conn             *h3;

    ngx_connection_t           *connection;
    ngx_http_connection_t      *http_connection;

    ngx_pool_t                 *pool;

    ngx_uint_t                  processing;

    ngx_rbtree_t                streams;
    ngx_rbtree_node_t           streams_sentinel;

    ngx_connection_t           *free_fake_connections;
};


struct ngx_http_v3_stream_s {
    ngx_rbtree_node_t          node;

    uint64_t                   id;

    ngx_http_request_t        *request;

    ngx_http_v3_connection_t  *connection;

    ngx_array_t               *cookies;

    ngx_http_v3_stream_t      *next;

    ngx_uint_t                 headers_sent:1;
    ngx_uint_t                 in_closed:1;
    ngx_uint_t                 out_closed:1;
    ngx_uint_t                 skip_data:1;
    ngx_uint_t                 blocked:1;
};


typedef struct {
    ngx_str_t                        name;
    ngx_str_t                        value;
} ngx_http_v3_header_t;


void ngx_http_v3_init(ngx_event_t *rev);

ngx_int_t ngx_http_v3_read_request_body(ngx_http_request_t *r);
ngx_int_t ngx_http_v3_read_unbuffered_request_body(ngx_http_request_t *r);

ngx_int_t ngx_http_v3_send_response(ngx_http_request_t *r);

void ngx_http_v3_close_stream(ngx_http_v3_stream_t *stream, ngx_int_t rc);
void ngx_http_v3_stop_stream_read(ngx_http_v3_stream_t *stream, ngx_int_t rc);


#endif /* _NGX_HTTP_V3_H_INCLUDED_ */
