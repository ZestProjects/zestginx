
/*
 * Copyright (C) Cloudflare, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_v3_module.h>


typedef struct {
    ngx_str_t           name;
    ngx_uint_t          offset;
    ngx_uint_t          hash;
    ngx_http_header_t  *hh;
} ngx_http_v3_parse_header_t;


/* errors */
#define NGX_HTTP_V3_NO_ERROR                     0x0100
#define NGX_HTTP_V3_PROTOCOL_ERROR               0x0101
#define NGX_HTTP_V3_INTERNAL_ERROR               0x0102


static void ngx_http_v3_handler(ngx_connection_t *c);

static void ngx_http_v3_idle_handler(ngx_connection_t *c);

static void ngx_http_v3_handle_connection(ngx_http_v3_connection_t *h3c);

static ngx_http_v3_stream_t *ngx_http_v3_stream_lookup(
    ngx_http_v3_connection_t *h3c, ngx_uint_t stream_id);
static ngx_http_v3_stream_t *ngx_http_v3_create_stream(
    ngx_http_v3_connection_t *h3c);
static void ngx_http_v3_close_stream_handler(ngx_event_t *ev);

static ngx_int_t ngx_http_v3_validate_header(ngx_http_request_t *r,
    ngx_http_v3_header_t *header);
static ngx_int_t ngx_http_v3_pseudo_header(ngx_http_request_t *r,
    ngx_http_v3_header_t *header);
static ngx_int_t ngx_http_v3_parse_path(ngx_http_request_t *r,
    ngx_str_t *value);
static ngx_int_t ngx_http_v3_parse_method(ngx_http_request_t *r,
    ngx_str_t *value);
static ngx_int_t ngx_http_v3_parse_scheme(ngx_http_request_t *r,
    ngx_str_t *value);
static ngx_int_t ngx_http_v3_parse_authority(ngx_http_request_t *r,
    ngx_str_t *value);
static ngx_int_t ngx_http_v3_parse_header(ngx_http_request_t *r,
    ngx_http_v3_parse_header_t *header, ngx_str_t *value);
static ngx_int_t ngx_http_v3_cookie(ngx_http_request_t *r,
    ngx_http_v3_header_t *header);
static ngx_int_t ngx_http_v3_construct_cookie_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_v3_construct_request_line(ngx_http_request_t *r);

static void ngx_http_v3_run_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_v3_process_request_body(ngx_http_request_t *r,
    ngx_uint_t do_read, ngx_uint_t last);
static ngx_int_t ngx_http_v3_filter_request_body(ngx_http_request_t *r);
static void ngx_http_v3_read_client_request_body_handler(ngx_http_request_t *r);

static ngx_chain_t *ngx_http_v3_send_chain(ngx_connection_t *fc,
    ngx_chain_t *in, off_t limit);

static void ngx_http_v3_finalize_connection(ngx_http_v3_connection_t *h3c,
    ngx_uint_t status);

static void ngx_http_v3_pool_cleanup(void *data);


static ngx_http_v3_parse_header_t  ngx_http_v3_parse_headers[] = {
    { ngx_string("host"),
      offsetof(ngx_http_headers_in_t, host), 0, NULL },

    { ngx_string("accept-encoding"),
      offsetof(ngx_http_headers_in_t, accept_encoding), 0, NULL },

    { ngx_string("accept-language"),
      offsetof(ngx_http_headers_in_t, accept_language), 0, NULL },

    { ngx_string("user-agent"),
      offsetof(ngx_http_headers_in_t, user_agent), 0, NULL },

    { ngx_null_string, 0, 0, NULL }
};


void
ngx_http_v3_init(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_pool_cleanup_t        *cln;
    ngx_http_connection_t     *hc;
    ngx_http_v3_srv_conf_t    *h3scf;
    ngx_http_v3_connection_t  *h3c;

    c = rev->data;
    hc = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "init http3 connection");

    c->log->action = "processing HTTP/3 connection";

    h3c = ngx_pcalloc(c->pool, sizeof(ngx_http_v3_connection_t));
    if (h3c == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    h3scf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_v3_module);

    h3c->h3 = quiche_h3_conn_new_with_transport(c->quic->conn, h3scf->http3);
    if (h3c->h3 == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    h3c->http_connection = hc;

    h3c->connection = c;

    h3c->pool = c->pool;

    c->data = h3c;

    c->quic->handler = ngx_http_v3_handler;

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    cln->handler = ngx_http_v3_pool_cleanup;
    cln->data = h3c;

    ngx_rbtree_init(&h3c->streams, &h3c->streams_sentinel,
                    ngx_rbtree_insert_value);
}


static int
ngx_http_v3_for_each_header(uint8_t *name, size_t name_len,
    uint8_t *value, size_t value_len, void *argp)
{
    ngx_int_t                   rc;
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_http_request_t         *r;
    ngx_http_v3_header_t        header;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_main_conf_t  *cmcf;

    static ngx_str_t cookie = ngx_string("cookie");

    r = argp;

    /* Duplicate the header name because we don't own it. */
    header.name.data = ngx_pnalloc(r->pool, name_len);
    if (header.name.data == NULL) {
        return NGX_ERROR;
    }
    header.name.len = name_len;

    ngx_memcpy(header.name.data, name, name_len);

    /* Duplicate the header value because we don't own it. Some of the
     * functions that process headers require a NULL-terminated string,
     * so allocate enough memory for that. */
    header.value.data = ngx_pcalloc(r->pool, value_len + 1);
    if (header.value.data == NULL) {
        return NGX_ERROR;
    }
    header.value.len = value_len;

    ngx_memcpy(header.value.data, value, value_len);

    if (ngx_http_v3_validate_header(r, &header) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Check for pseudo-header. */
    if (header.name.data[0] == ':') {
        rc = ngx_http_v3_pseudo_header(r, &header);

        if (rc == NGX_OK) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http3 header: \":%V: %V\"",
                           &header.name, &header.value);

            return NGX_OK;
        }

        return NGX_ERROR;
    }

    if (r->invalid_header) {
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        if (cscf->ignore_invalid_headers) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid header: \"%V\"", &header.name);

            return NGX_ERROR;
        }
    }

    /* Handle Cookie header separately. Not sure why, but the HTTP/2 code does
     * the same. */
    if (header.name.len == cookie.len
        && ngx_memcmp(header.name.data, cookie.data, cookie.len) == 0)
    {
        if (ngx_http_v3_cookie(r, &header) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        h = ngx_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->key.len = header.name.len;
        h->key.data = header.name.data;

        /*
         * TODO Optimization: precalculate hash
         * and handler for indexed headers.
         */
        h->hash = ngx_hash_key(h->key.data, h->key.len);

        h->value.len = header.value.len;
        h->value.data = header.value.data;

        h->lowcase_key = h->key.data;

        cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

        hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                           h->lowcase_key, h->key.len);

        if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 header: \"%V: %V\"",
                   &header.name, &header.value);

    return NGX_OK;
}


static void
ngx_http_v3_process_headers(ngx_connection_t *c, quiche_h3_event *ev,
    int64_t stream_id)
{
    int                        rc;
    ngx_http_v3_stream_t      *stream;
    ngx_http_v3_srv_conf_t    *h3scf;
    ngx_http_v3_connection_t  *h3c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 process headers");

    h3c = c->data;

    h3scf = ngx_http_get_module_srv_conf(h3c->http_connection->conf_ctx,
                                         ngx_http_v3_module);

    if (h3c->connection->requests >= h3scf->max_requests) {
        ngx_http_v3_finalize_connection(h3c, NGX_HTTP_V3_NO_ERROR);
        return;
    }

    /* Create a new stream to handle the incoming request. */
    stream = ngx_http_v3_create_stream(h3c);
    if (stream == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to create HTTP/3 stream");

        ngx_http_v3_finalize_connection(h3c, NGX_HTTP_V3_INTERNAL_ERROR);
        return;
    }

    stream->id = stream_id;

    stream->node.key = stream_id;

    ngx_rbtree_insert(&h3c->streams, &stream->node);

    /* Populate ngx_http_request_t from raw HTTP/3 headers. */
    rc = quiche_h3_event_for_each_header(ev,
        ngx_http_v3_for_each_header, stream->request);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "received invalid HTTP/3 headers");

        ngx_http_v3_finalize_connection(h3c, NGX_HTTP_V3_INTERNAL_ERROR);
        return;
    }

    stream->in_closed = !quiche_h3_event_headers_has_body(ev);

    ngx_http_v3_run_request(stream->request);
}


static ngx_int_t
ngx_http_v3_process_data(ngx_connection_t *c, int64_t stream_id)
{
    int                        rc;
    ngx_http_request_t        *r;
    ngx_http_v3_stream_t      *stream;
    ngx_http_v3_connection_t  *h3c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 process data");

    h3c = c->data;

    stream = ngx_http_v3_stream_lookup(h3c, stream_id);

    if (stream == NULL) {

        return NGX_OK;
    }

    if (stream->skip_data) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "skipping http3 DATA frame");

        return NGX_OK;
    }

    r = stream->request;

    if (!r->request_body) {
        return NGX_AGAIN;
    }

    rc = ngx_http_v3_process_request_body(r, 1, stream->in_closed);

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (rc != NGX_OK) {
        stream->skip_data = 1;
        ngx_http_finalize_request(r, rc);
    }

    return NGX_OK;
}


static void
ngx_http_v3_process_blocked_streams(ngx_http_v3_connection_t *h3c)
{
    ngx_event_t               *wev;
    quiche_stream_iter        *writable;
    ngx_http_v3_stream_t      *stream;
    uint64_t                   stream_id;

    writable = quiche_conn_writable(h3c->connection->quic->conn);

    while (quiche_stream_iter_next(writable, &stream_id)) {
        stream = ngx_http_v3_stream_lookup(h3c, stream_id);

        if (stream == NULL) {
            continue;
        }

        if (!stream->blocked) {
            continue;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, h3c->connection->log, 0,
                       "http3 stream unblocked %ui", stream->id);

        stream->blocked = 0;

        wev = stream->request->connection->write;

        wev->active = 0;
        wev->ready = 1;

        if (!stream->headers_sent) {
            ngx_http_v3_send_response(stream->request);
        }

        if (!wev->delayed) {
            wev->handler(wev);
        }
    }

    quiche_stream_iter_free(writable);
}


static void
ngx_http_v3_handler(ngx_connection_t *c)
{
    ngx_http_v3_connection_t  *h3c;
    ngx_http_v3_stream_t      *stream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 handler");

    h3c = c->data;

    if (c->read->timedout) {
        ngx_http_v3_finalize_connection(h3c, NGX_HTTP_V3_PROTOCOL_ERROR);
        return;
    }

    if (c->error) {
        ngx_http_v3_finalize_connection(h3c, NGX_HTTP_V3_INTERNAL_ERROR);
        return;
    }

    ngx_http_v3_process_blocked_streams(h3c);

    while (!c->error) {
        quiche_h3_event  *ev;

        int64_t stream_id = quiche_h3_conn_poll(h3c->h3, c->quic->conn, &ev);
        if (stream_id == QUICHE_H3_ERR_DONE) {
            break;
        }

        if (stream_id < 0) {
            ngx_http_v3_finalize_connection(h3c, NGX_HTTP_V3_PROTOCOL_ERROR);
            return;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h3c->connection->log, 0,
                       "http3 event stream:%ui ev:%ui", stream_id,
                       quiche_h3_event_type(ev));

        switch (quiche_h3_event_type(ev)) {
            case QUICHE_H3_EVENT_HEADERS: {
                ngx_http_v3_process_headers(c, ev, stream_id);
                break;
            }

            case QUICHE_H3_EVENT_DATA: {
                if (ngx_http_v3_process_data(c, stream_id) == NGX_AGAIN) {
                    quiche_h3_event_free(ev);

                    ngx_http_v3_handle_connection(h3c);
                    return;
                }

                break;
            }

            case QUICHE_H3_EVENT_FINISHED: {
                /* Lookup stream. If there isn't one, it means it has already
                 * been closed, so ignore the event. */
                stream = ngx_http_v3_stream_lookup(h3c, stream_id);

                if (stream != NULL && !stream->in_closed) {
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                                   "http3 finished");

                    stream->in_closed = 1;

                    /* Flush request body that was buffered. */
                    if (stream->request->request_body) {
                        ngx_http_v3_process_request_body(stream->request, 0, 1);
                    }
                }

                break;
            }

            case QUICHE_H3_EVENT_DATAGRAM:
                break;

            case QUICHE_H3_EVENT_GOAWAY:
                break;
        }

        quiche_h3_event_free(ev);
    }

    ngx_http_v3_handle_connection(h3c);
}


static void
ngx_http_v3_idle_handler(ngx_connection_t *c)
{
    ngx_http_v3_connection_t  *h3c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 idle handler");

    h3c = c->data;

    if (c->read->timedout) {
        ngx_http_v3_finalize_connection(h3c, NGX_HTTP_V3_NO_ERROR);
        return;
    }

    if (c->error) {
        ngx_http_v3_finalize_connection(h3c, NGX_HTTP_V3_INTERNAL_ERROR);
        return;
    }

    if (!quiche_conn_is_readable(c->quic->conn)) {
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    c->quic->handler = ngx_http_v3_handler;

    ngx_http_v3_handler(c);
}


static void
ngx_http_v3_handle_connection(ngx_http_v3_connection_t *h3c)
{
    ngx_connection_t        *c;
    ngx_http_v3_srv_conf_t  *h3scf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h3c->connection->log, 0,
                   "http3 handle connection");

    c = h3c->connection;

    if (h3c->processing || c->error) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h3c->connection->log, 0,
                   "http3 connection is idle");

    h3scf = ngx_http_get_module_srv_conf(h3c->http_connection->conf_ctx,
                                         ngx_http_v3_module);

    c->quic->handler = ngx_http_v3_idle_handler;

    ngx_add_timer(c->read, h3scf->idle_timeout);
}


static ngx_http_v3_stream_t *
ngx_http_v3_create_stream(ngx_http_v3_connection_t *h3c)
{
    ngx_log_t                 *log;
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *fc;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_request_t        *r;
    ngx_http_v3_stream_t      *stream;
    ngx_http_core_srv_conf_t  *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h3c->connection->log, 0,
                   "http3 create stream");

    fc = h3c->free_fake_connections;

    if (fc) {
        h3c->free_fake_connections = fc->data;

        rev = fc->read;
        wev = fc->write;
        log = fc->log;
        ctx = log->data;

    } else {
        fc = ngx_palloc(h3c->pool, sizeof(ngx_connection_t));
        if (fc == NULL) {
            return NULL;
        }

        rev = ngx_palloc(h3c->pool, sizeof(ngx_event_t));
        if (rev == NULL) {
            return NULL;
        }

        wev = ngx_palloc(h3c->pool, sizeof(ngx_event_t));
        if (wev == NULL) {
            return NULL;
        }

        log = ngx_palloc(h3c->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            return NULL;
        }

        ctx = ngx_palloc(h3c->pool, sizeof(ngx_http_log_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        ctx->connection = fc;
        ctx->request = NULL;
        ctx->current_request = NULL;
    }

    ngx_memcpy(log, h3c->connection->log, sizeof(ngx_log_t));

    log->data = ctx;

    ngx_memzero(rev, sizeof(ngx_event_t));

    rev->data = fc;
    rev->ready = 1;
    rev->handler = ngx_http_v3_close_stream_handler;
    rev->log = log;

    ngx_memcpy(wev, rev, sizeof(ngx_event_t));

    wev->write = 1;

    ngx_memcpy(fc, h3c->connection, sizeof(ngx_connection_t));

    fc->data = h3c->http_connection;
    fc->quic = h3c->connection->quic;
    fc->read = rev;
    fc->write = wev;
    fc->sent = 0;
    fc->buffer = NULL;
    fc->log = log;
    fc->buffered = 0;
    fc->sndlowat = 1;
    fc->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;

    fc->send_chain = ngx_http_v3_send_chain;
    fc->need_last_buf = 1;

    r = ngx_http_create_request(fc);
    if (r == NULL) {
        return NULL;
    }

    ngx_str_set(&r->http_protocol, "HTTP/3");

    r->http_version = NGX_HTTP_VERSION_3;
    r->valid_location = 1;

    fc->data = r;
    h3c->connection->requests++;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    r->header_in = ngx_create_temp_buf(r->pool,
                                       cscf->client_header_buffer_size);
    if (r->header_in == NULL) {
        ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;

    stream = ngx_pcalloc(h3c->pool, sizeof(ngx_http_v3_stream_t));
    if (stream == NULL) {
        ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->qstream = stream;

    stream->request = r;
    stream->connection = h3c;

    h3c->processing++;

    return stream;
}


static ngx_http_v3_stream_t *
ngx_http_v3_stream_lookup(ngx_http_v3_connection_t *h3c, ngx_uint_t stream_id)
{
    ngx_rbtree_node_t  *node, *sentinel;

    node = h3c->streams.root;
    sentinel = h3c->streams.sentinel;

    while (node != sentinel) {

        if (stream_id < node->key) {
            node = node->left;
            continue;
        }

        if (stream_id > node->key) {
            node = node->right;
            continue;
        }

        /* stream_id == node->key */

        return (ngx_http_v3_stream_t *) node;
    }

    /* not found */

    return NULL;
}


/* The following functions are copied from the HTTP/2 module, and adapted to
 * work independently. In theory we could refactor the HTTP/2 module to expose
 * these functions, but that would be fairly invasive and likely cause more
 * merge conflicts in the future. */


static ngx_int_t
ngx_http_v3_validate_header(ngx_http_request_t *r, ngx_http_v3_header_t *header)
{
    u_char                     ch;
    ngx_uint_t                 i;
    ngx_http_core_srv_conf_t  *cscf;

    if (header->name.len == 0) {
        return NGX_ERROR;
    }

    r->invalid_header = 0;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    for (i = (header->name.data[0] == ':'); i != header->name.len; i++) {
        ch = header->name.data[i];

        if ((ch >= 'a' && ch <= 'z')
            || (ch == '-')
            || (ch >= '0' && ch <= '9')
            || (ch == '_' && cscf->underscores_in_headers))
        {
            continue;
        }

        if (ch == '\0' || ch == LF || ch == CR || ch == ':'
            || (ch >= 'A' && ch <= 'Z'))
        {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid header name: \"%V\"",
                          &header->name);

            return NGX_ERROR;
        }

        r->invalid_header = 1;
    }

    for (i = 0; i != header->value.len; i++) {
        ch = header->value.data[i];

        if (ch == '\0' || ch == LF || ch == CR) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent header \"%V\" with "
                          "invalid value: \"%V\"",
                          &header->name, &header->value);

            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_pseudo_header(ngx_http_request_t *r, ngx_http_v3_header_t *header)
{
    header->name.len--;
    header->name.data++;

    switch (header->name.len) {
    case 4:
        if (ngx_memcmp(header->name.data, "path", sizeof("path") - 1)
            == 0)
        {
            return ngx_http_v3_parse_path(r, &header->value);
        }

        break;

    case 6:
        if (ngx_memcmp(header->name.data, "method", sizeof("method") - 1)
            == 0)
        {
            return ngx_http_v3_parse_method(r, &header->value);
        }

        if (ngx_memcmp(header->name.data, "scheme", sizeof("scheme") - 1)
            == 0)
        {
            return ngx_http_v3_parse_scheme(r, &header->value);
        }

        break;

    case 9:
        if (ngx_memcmp(header->name.data, "authority", sizeof("authority") - 1)
            == 0)
        {
            return ngx_http_v3_parse_authority(r, &header->value);
        }

        break;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "client sent unknown pseudo-header \":%V\"",
                  &header->name);

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_v3_parse_path(ngx_http_request_t *r, ngx_str_t *value)
{
    if (r->unparsed_uri.len) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :path header");

        return NGX_DECLINED;
    }

    if (value->len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent empty :path header");

        return NGX_DECLINED;
    }

    r->uri_start = value->data;
    r->uri_end = value->data + value->len;

    if (ngx_http_parse_uri(r) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent invalid :path header: \"%V\"", value);

        return NGX_DECLINED;
    }

    if (ngx_http_process_request_uri(r) != NGX_OK) {
        /*
         * request has been finalized already
         * in ngx_http_process_request_uri()
         */
        return NGX_ABORT;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_parse_method(ngx_http_request_t *r, ngx_str_t *value)
{
    size_t         k, len;
    ngx_uint_t     n;
    const u_char  *p, *m;

    /*
     * This array takes less than 256 sequential bytes,
     * and if typical CPU cache line size is 64 bytes,
     * it is prefetched for 4 load operations.
     */
    static const struct {
        u_char            len;
        const u_char      method[11];
        uint32_t          value;
    } tests[] = {
        { 3, "GET",       NGX_HTTP_GET },
        { 4, "POST",      NGX_HTTP_POST },
        { 4, "HEAD",      NGX_HTTP_HEAD },
        { 7, "OPTIONS",   NGX_HTTP_OPTIONS },
        { 8, "PROPFIND",  NGX_HTTP_PROPFIND },
        { 3, "PUT",       NGX_HTTP_PUT },
        { 5, "MKCOL",     NGX_HTTP_MKCOL },
        { 6, "DELETE",    NGX_HTTP_DELETE },
        { 4, "COPY",      NGX_HTTP_COPY },
        { 4, "MOVE",      NGX_HTTP_MOVE },
        { 9, "PROPPATCH", NGX_HTTP_PROPPATCH },
        { 4, "LOCK",      NGX_HTTP_LOCK },
        { 6, "UNLOCK",    NGX_HTTP_UNLOCK },
        { 5, "PATCH",     NGX_HTTP_PATCH },
        { 5, "TRACE",     NGX_HTTP_TRACE }
    }, *test;

    if (r->method_name.len) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :method header");

        return NGX_DECLINED;
    }

    if (value->len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent empty :method header");

        return NGX_DECLINED;
    }

    r->method_name.len = value->len;
    r->method_name.data = value->data;

    len = r->method_name.len;
    n = sizeof(tests) / sizeof(tests[0]);
    test = tests;

    do {
        if (len == test->len) {
            p = r->method_name.data;
            m = test->method;
            k = len;

            do {
                if (*p++ != *m++) {
                    goto next;
                }
            } while (--k);

            r->method = test->value;
            return NGX_OK;
        }

    next:
        test++;

    } while (--n);

    p = r->method_name.data;

    do {
        if ((*p < 'A' || *p > 'Z') && *p != '_' && *p != '-') {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid method: \"%V\"",
                          &r->method_name);

            return NGX_DECLINED;
        }

        p++;

    } while (--len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_parse_scheme(ngx_http_request_t *r, ngx_str_t *value)
{
    u_char      c, ch;
    ngx_uint_t  i;

    if (r->schema.len) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :scheme header");

        return NGX_DECLINED;
    }

    if (value->len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent empty :scheme header");

        return NGX_DECLINED;
    }

    for (i = 0; i < value->len; i++) {
        ch = value->data[i];

        c = (u_char) (ch | 0x20);
        if (c >= 'a' && c <= 'z') {
            continue;
        }

        if (((ch >= '0' && ch <= '9') || ch == '+' || ch == '-' || ch == '.')
            && i > 0)
        {
            continue;
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent invalid :scheme header: \"%V\"", value);

        return NGX_DECLINED;
    }

    r->schema = *value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_parse_authority(ngx_http_request_t *r, ngx_str_t *value)
{
    return ngx_http_v3_parse_header(r, &ngx_http_v3_parse_headers[0], value);
}


static ngx_int_t
ngx_http_v3_parse_header(ngx_http_request_t *r,
    ngx_http_v3_parse_header_t *header, ngx_str_t *value)
{
    ngx_table_elt_t            *h;
    ngx_http_core_main_conf_t  *cmcf;

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->key.len = header->name.len;
    h->key.data = header->name.data;
    h->lowcase_key = header->name.data;

    if (header->hh == NULL) {
        header->hash = ngx_hash_key(header->name.data, header->name.len);

        cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

        header->hh = ngx_hash_find(&cmcf->headers_in_hash, header->hash,
                                   h->lowcase_key, h->key.len);
        if (header->hh == NULL) {
            return NGX_ERROR;
        }
    }

    h->hash = header->hash;

    h->value.len = value->len;
    h->value.data = value->data;

    if (header->hh->handler(r, h, header->hh->offset) != NGX_OK) {
        /* header handler has already finalized request */
        return NGX_ABORT;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_construct_request_line(ngx_http_request_t *r)
{
    u_char  *p;

    static const u_char ending[] = " HTTP/3";

    if (r->method_name.len == 0
        || r->schema.len == 0
        || r->unparsed_uri.len == 0)
    {
        if (r->method_name.len == 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent no :method header");

        } else if (r->schema.len == 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent no :scheme header");

        } else {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent no :path header");
        }

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    r->request_line.len = r->method_name.len + 1
                          + r->unparsed_uri.len
                          + sizeof(ending) - 1;

    p = ngx_pnalloc(r->pool, r->request_line.len + 1);
    if (p == NULL) {
        ngx_http_v3_close_stream(r->qstream, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    r->request_line.data = p;

    p = ngx_cpymem(p, r->method_name.data, r->method_name.len);

    *p++ = ' ';

    p = ngx_cpymem(p, r->unparsed_uri.data, r->unparsed_uri.len);

    ngx_memcpy(p, ending, sizeof(ending));

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 request line: \"%V\"", &r->request_line);

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_cookie(ngx_http_request_t *r, ngx_http_v3_header_t *header)
{
    ngx_str_t    *val;
    ngx_array_t  *cookies;

    cookies = r->qstream->cookies;

    if (cookies == NULL) {
        cookies = ngx_array_create(r->pool, 2, sizeof(ngx_str_t));
        if (cookies == NULL) {
            return NGX_ERROR;
        }

        r->qstream->cookies = cookies;
    }

    val = ngx_array_push(cookies);
    if (val == NULL) {
        return NGX_ERROR;
    }

    val->len = header->value.len;
    val->data = header->value.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_construct_cookie_header(ngx_http_request_t *r)
{
    u_char                     *buf, *p, *end;
    size_t                      len;
    ngx_str_t                  *vals;
    ngx_uint_t                  i;
    ngx_array_t                *cookies;
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_http_core_main_conf_t  *cmcf;

    static ngx_str_t cookie = ngx_string("cookie");

    cookies = r->qstream->cookies;

    if (cookies == NULL) {
        return NGX_OK;
    }

    vals = cookies->elts;

    i = 0;
    len = 0;

    do {
        len += vals[i].len + 2;
    } while (++i != cookies->nelts);

    len -= 2;

    buf = ngx_pnalloc(r->pool, len + 1);
    if (buf == NULL) {
        ngx_http_v3_close_stream(r->qstream, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    p = buf;
    end = buf + len;

    for (i = 0; /* void */ ; i++) {

        p = ngx_cpymem(p, vals[i].data, vals[i].len);

        if (p == end) {
            *p = '\0';
            break;
        }

        *p++ = ';'; *p++ = ' ';
    }

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        ngx_http_v3_close_stream(r->qstream, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                    ngx_hash('c', 'o'), 'o'), 'k'), 'i'), 'e');

    h->key.len = cookie.len;
    h->key.data = cookie.data;

    h->value.len = len;
    h->value.data = buf;

    h->lowcase_key = cookie.data;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh == NULL) {
        ngx_http_v3_close_stream(r->qstream, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    if (hh->handler(r, h, hh->offset) != NGX_OK) {
        /*
         * request has been finalized already
         * in ngx_http_process_multi_header_lines()
         */
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_v3_run_request(ngx_http_request_t *r)
{
    if (ngx_http_v3_construct_request_line(r) != NGX_OK) {
        return;
    }

    if (ngx_http_v3_construct_cookie_header(r) != NGX_OK) {
        return;
    }

    r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;

    if (ngx_http_process_request_header(r) != NGX_OK) {
        return;
    }

    if (r->headers_in.content_length_n > 0 && r->qstream->in_closed) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client prematurely closed stream");

        r->qstream->skip_data = 1;

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }

    if (r->headers_in.content_length_n == -1 && !r->qstream->in_closed) {
        r->headers_in.chunked = 1;
    }

    ngx_http_process_request(r);
}


ngx_int_t
ngx_http_v3_read_request_body(ngx_http_request_t *r)
{
    off_t                      len;
    ngx_http_v3_stream_t      *stream;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 read request body");

    stream = r->qstream;
    rb = r->request_body;

    if (stream->skip_data) {
        r->request_body_no_buffering = 0;
        rb->post_handler(r);
        return NGX_OK;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    len = r->headers_in.content_length_n;

    if (r->request_body_no_buffering && !stream->in_closed) {

        if (len < 0 || len > (off_t) clcf->client_body_buffer_size) {
            len = clcf->client_body_buffer_size;
        }

        rb->buf = ngx_create_temp_buf(r->pool, (size_t) len);

    } else if (len >= 0 && len <= (off_t) clcf->client_body_buffer_size
               && !r->request_body_in_file_only)
    {
        rb->buf = ngx_create_temp_buf(r->pool, (size_t) len);

    } else {
        rb->buf = ngx_calloc_buf(r->pool);

        if (rb->buf != NULL) {
            rb->buf->sync = 1;
        }
    }

    if (rb->buf == NULL) {
        stream->skip_data = 1;

        /* disable stream read to avoid pointless data events */
        ngx_http_v3_stop_stream_read(stream, 0);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rb->rest = 1;

    if (stream->in_closed) {
        r->request_body_no_buffering = 0;

        return ngx_http_v3_process_request_body(r, 0, 1);
    }

    /* TODO: set timer */
    ngx_add_timer(r->connection->read, clcf->client_body_timeout);

    r->read_event_handler = ngx_http_v3_read_client_request_body_handler;
    r->write_event_handler = ngx_http_request_empty_handler;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_v3_process_request_body(ngx_http_request_t *r, ngx_uint_t do_read,
    ngx_uint_t last)
{
    ssize_t                    len = 0;
    ngx_buf_t                 *buf;
    ngx_int_t                  rc;
    ngx_connection_t          *c, *fc;
    ngx_http_v3_connection_t  *h3c;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    fc = r->connection;
    h3c = r->qstream->connection;
    c = h3c->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 process request body");

    rb = r->request_body;
    buf = rb->buf;

    if (buf->sync) {
        buf->pos = buf->start;
        buf->last = buf->start;

        r->request_body_in_file_only = 1;
    }

    if (do_read) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 reading %z bytes of request body",
                       buf->end - buf->last);

        if (buf->last == buf->end) {
            return NGX_AGAIN;
        }

        len = quiche_h3_recv_body(h3c->h3, c->quic->conn, r->qstream->id,
                                  buf->last, buf->end - buf->last);

        if (len == QUICHE_H3_ERR_DONE) {
            return NGX_AGAIN;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 read %z bytes of request body", len);

        buf->last += len;
    }

    if (last) {
        rb->rest = 0;

        if (fc->read->timer_set) {
            ngx_del_timer(fc->read);
        }

        if (r->request_body_no_buffering) {
            ngx_post_event(fc->read, &ngx_posted_events);
            return NGX_OK;
        }

        rc = ngx_http_v3_filter_request_body(r);

        if (rc != NGX_OK) {
            return rc;
        }

        if (buf->sync) {
            /* prevent reusing this buffer in the upstream module */
            rb->buf = NULL;
        }

        if (r->headers_in.chunked) {
            r->headers_in.content_length_n = rb->received;
        }

        r->read_event_handler = ngx_http_block_reading;
        rb->post_handler(r);

        return NGX_OK;
    }

    if (len == 0) {
        return NGX_OK;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ngx_add_timer(fc->read, clcf->client_body_timeout);

    if (r->request_body_no_buffering) {
        ngx_post_event(fc->read, &ngx_posted_events);
        return NGX_AGAIN;
    }

    if (buf->sync) {
        return ngx_http_v3_filter_request_body(r);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_filter_request_body(ngx_http_request_t *r)
{
    ngx_buf_t                 *b, *buf;
    ngx_int_t                  rc;
    ngx_chain_t               *cl;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 filter request body");

    rb = r->request_body;
    buf = rb->buf;

    if (buf->pos == buf->last && rb->rest) {
        cl = NULL;
        goto update;
    }

    cl = ngx_chain_get_free_buf(r->pool, &rb->free);
    if (cl == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = cl->buf;

    ngx_memzero(b, sizeof(ngx_buf_t));

    if (buf->pos != buf->last) {
        r->request_length += buf->last - buf->pos;
        rb->received += buf->last - buf->pos;

        if (r->headers_in.content_length_n != -1) {
            if (rb->received > r->headers_in.content_length_n) {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "client intended to send body data "
                              "larger than declared");

                return NGX_HTTP_BAD_REQUEST;
            }

        } else {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

            if (clcf->client_max_body_size
                && rb->received > clcf->client_max_body_size)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "client intended to send too large chunked body: "
                              "%O bytes", rb->received);

                return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
            }
        }

        b->temporary = 1;
        b->pos = buf->pos;
        b->last = buf->last;
        b->start = b->pos;
        b->end = b->last;

        buf->pos = buf->last;
    }

    if (!rb->rest) {
        if (r->headers_in.content_length_n != -1
            && r->headers_in.content_length_n != rb->received)
        {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client prematurely closed stream: "
                          "only %O out of %O bytes of request body received",
                          rb->received, r->headers_in.content_length_n);

            return NGX_HTTP_BAD_REQUEST;
        }

        b->last_buf = 1;
    }

    b->tag = (ngx_buf_tag_t) &ngx_http_v3_filter_request_body;
    b->flush = r->request_body_no_buffering;

update:

    rc = ngx_http_top_request_body_filter(r, cl);

    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &cl,
                            (ngx_buf_tag_t) &ngx_http_v3_filter_request_body);

    return rc;
}


static void
ngx_http_v3_read_client_request_body_handler(ngx_http_request_t *r)
{
    ngx_connection_t  *fc;

    fc = r->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                   "http3 read client request body handler");

    if (fc->read->timedout) {
        ngx_log_error(NGX_LOG_INFO, fc->log, NGX_ETIMEDOUT, "client timed out");

        fc->timedout = 1;
        r->qstream->skip_data = 1;

        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (fc->error) {
        ngx_log_error(NGX_LOG_INFO, fc->log, 0,
                      "client prematurely closed stream");

        r->qstream->skip_data = 1;

        ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }
}


ngx_int_t
ngx_http_v3_read_unbuffered_request_body(ngx_http_request_t *r)
{
    ngx_buf_t                 *buf;
    ngx_int_t                  rc;
    ngx_connection_t          *fc;
    ngx_http_v3_stream_t      *stream;

    stream = r->qstream;
    fc = r->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                   "http3 read unbuffered request body");

    if (fc->read->timedout) {
        stream->skip_data = 1;
        fc->timedout = 1;

        /* disable stream read to avoid pointless data events */
        ngx_http_v3_stop_stream_read(stream, 0);

        return NGX_HTTP_REQUEST_TIME_OUT;
    }

    if (fc->error) {
        stream->skip_data = 1;
        return NGX_HTTP_BAD_REQUEST;
    }

    rc = ngx_http_v3_filter_request_body(r);

    if (rc != NGX_OK) {
        stream->skip_data = 1;

        /* disable stream read to avoid pointless data events */
        ngx_http_v3_stop_stream_read(stream, 0);

        return rc;
    }

    if (!r->request_body->rest) {
        return NGX_OK;
    }

    if (r->request_body->busy != NULL) {
        return NGX_AGAIN;
    }

    buf = r->request_body->buf;

    buf->pos = buf->start;
    buf->last = buf->start;

    ngx_post_event(stream->connection->connection->read, &ngx_posted_events);

    return NGX_AGAIN;
}


/* End of functions copied from HTTP/2 module. */


ngx_int_t
ngx_http_v3_push_response_headers(ngx_http_request_t *r, ngx_array_t *out)
{
    u_char                    *tmp;
    size_t                     len;
    ngx_str_t                  host, location;
    ngx_uint_t                 i, port;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *header;
    ngx_connection_t          *fc;
    quiche_h3_header          *h;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;
    u_char                     addr[NGX_SOCKADDR_STRLEN];

    fc = r->connection;

    if (r->method == NGX_HTTP_HEAD) {
        r->header_only = 1;
    }

    switch (r->headers_out.status) {

    case NGX_HTTP_OK:
        break;

    case NGX_HTTP_NO_CONTENT:
        r->header_only = 1;

        ngx_str_null(&r->headers_out.content_type);

        r->headers_out.content_length = NULL;
        r->headers_out.content_length_n = -1;

        r->headers_out.last_modified_time = -1;
        r->headers_out.last_modified = NULL;
        break;

    case NGX_HTTP_PARTIAL_CONTENT:
        break;

    case NGX_HTTP_NOT_MODIFIED:
        r->header_only = 1;
        break;

    default:
        r->headers_out.last_modified_time = -1;
        r->headers_out.last_modified = NULL;
    }

    /* Generate :status pseudo-header. */
    {
        h = ngx_array_push(out);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->name = (u_char *) ":status";
        h->name_len = sizeof(":status") - 1;

        tmp = ngx_pnalloc(r->pool, sizeof("418") - 1);
        if (tmp == NULL) {
            return NGX_ERROR;
        }

        h->value = tmp;
        h->value_len = ngx_sprintf(tmp, "%03ui", r->headers_out.status) - tmp;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /* Generate Server header.*/
    if (r->headers_out.server == NULL) {
        h = ngx_array_push(out);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->name = (u_char *) "server";
        h->name_len = sizeof("server") - 1;

        if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
            h->value = (u_char *) NGINX_VER;
            h->value_len = sizeof(NGINX_VER) - 1;

        } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
            h->value = (u_char *) NGINX_VER_BUILD;
            h->value_len = sizeof(NGINX_VER_BUILD) - 1;

        } else {
            h->value = (u_char *) "nginx";
            h->value_len = sizeof("nginx") - 1;
        }
    }

    /* Generate Date header. */
    if (r->headers_out.date == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                       "http3 output header: \"date: %V\"",
                       &ngx_cached_http_time);

        h = ngx_array_push(out);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->name = (u_char *) "date";
        h->name_len = sizeof("date") - 1;

        h->value = ngx_cached_http_time.data;
        h->value_len = ngx_cached_http_time.len;
    }

    /* Generate Content-Type header. */
    if (r->headers_out.content_type.len) {
        h = ngx_array_push(out);
        if (h == NULL) {
            return NGX_ERROR;
        }

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            len = r->headers_out.content_type.len + sizeof("; charset=") - 1
                  + r->headers_out.charset.len;

            tmp = ngx_pnalloc(r->pool, len);
            if (tmp == NULL) {
                return NGX_ERROR;
            }

            tmp = ngx_cpymem(tmp, r->headers_out.content_type.data,
                             r->headers_out.content_type.len);

            tmp = ngx_cpymem(tmp, "; charset=", sizeof("; charset=") - 1);

            tmp = ngx_cpymem(tmp, r->headers_out.charset.data,
                             r->headers_out.charset.len);

            /* updated r->headers_out.content_type is also needed for logging */

            r->headers_out.content_type.len = len;
            r->headers_out.content_type.data = tmp - len;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                       "http3 output header: \"content-type: %V\"",
                       &r->headers_out.content_type);

        h->name = (u_char *) "content-type";
        h->name_len = sizeof("content-type") - 1;

        h->value = r->headers_out.content_type.data;
        h->value_len = r->headers_out.content_type.len;
    }

    /* Generate Content-Length header. */
    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        h = ngx_array_push(out);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->name = (u_char *) "content-length";
        h->name_len = sizeof("content-length") - 1;

        tmp = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
        if (tmp == NULL) {
            return NGX_ERROR;
        }

        h->value = tmp;
        h->value_len =
            ngx_sprintf(tmp, "%O", r->headers_out.content_length_n) - tmp;
    }

    /* Generate Last-Modified header. */
    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        h = ngx_array_push(out);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->name = (u_char *) "last-modified";
        h->name_len = sizeof("last-modified") - 1;

        tmp = ngx_pnalloc(r->pool, sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1);
        if (tmp == NULL) {
            return NGX_ERROR;
        }

        h->value = tmp;
        h->value_len =
            ngx_http_time(tmp, r->headers_out.last_modified_time) - tmp;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                       "http3 output header: \"last-modified: %*.s\"",
                       h->value_len, h->value);
    }

    /* Generate Location header. */
    if (r->headers_out.location && r->headers_out.location->value.len) {

        if (r->headers_out.location->value.data[0] == '/'
            && clcf->absolute_redirect)
        {
            if (clcf->server_name_in_redirect) {
                cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
                host = cscf->server_name;

            } else if (r->headers_in.server.len) {
                host = r->headers_in.server;

            } else {
                host.data = addr;
                host.len = NGX_SOCKADDR_STRLEN;

                if (ngx_connection_local_sockaddr(fc, &host, 0) != NGX_OK) {
                    return NGX_ERROR;
                }
            }

            port = ngx_inet_get_port(fc->local_sockaddr);

            location.len = sizeof("https://") - 1 + host.len
                           + r->headers_out.location->value.len;

            if (clcf->port_in_redirect) {

#if (NGX_HTTP_SSL)
                if (fc->ssl)
                    port = (port == 443) ? 0 : port;
                else
#endif
                    port = (port == 80) ? 0 : port;

            } else {
                port = 0;
            }

            if (port) {
                location.len += sizeof(":65535") - 1;
            }

            location.data = ngx_pnalloc(r->pool, location.len);
            if (location.data == NULL) {
                return NGX_ERROR;
            }

            tmp = ngx_cpymem(location.data, "http", sizeof("http") - 1);

#if (NGX_HTTP_SSL)
            if (fc->ssl) {
                *tmp++ = 's';
            }
#endif

            *tmp++ = ':'; *tmp++ = '/'; *tmp++ = '/';
            tmp = ngx_cpymem(tmp, host.data, host.len);

            if (port) {
                tmp = ngx_sprintf(tmp, ":%ui", port);
            }

            tmp = ngx_cpymem(tmp, r->headers_out.location->value.data,
                                  r->headers_out.location->value.len);

            /* update r->headers_out.location->value for possible logging */

            r->headers_out.location->value.len = tmp - location.data;
            r->headers_out.location->value.data = location.data;
            ngx_str_set(&r->headers_out.location->key, "Location");
        }

        r->headers_out.location->hash = 0;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                       "http3 output header: \"location: %V\"",
                       &r->headers_out.location->value);

        h = ngx_array_push(out);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->name = (u_char *) "location";
        h->name_len = sizeof("location") - 1;

        h->value = r->headers_out.location->value.data;
        h->value_len = r->headers_out.location->value.len;
    }

#if (NGX_HTTP_GZIP)
    /* Generate Vary header. */
    if (r->gzip_vary) {
        h = ngx_array_push(out);
        if (h == NULL) {
            return NGX_ERROR;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                       "http3 output header: \"vary: Accept-Encoding\"");

        h->name = (u_char *) "vary";
        h->name_len = sizeof("vary") - 1;

        h->value = (u_char *) "Accept-Encoding";
        h->value_len = sizeof("Accept-Encoding") - 1;
    }
#endif

    part = &r->headers_out.headers.part;
    header = part->elts;

    /* Generate all other headers. */
    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        h = ngx_array_push(out);
        if (h == NULL) {
            return NGX_ERROR;
        }

#if (NGX_DEBUG)
        if (fc->log->log_level & NGX_LOG_DEBUG_HTTP) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                           "http3 output header: \"%V: %V\"",
                           &header[i].key, &header[i].value);
        }
#endif

        h->name = header[i].key.data;
        h->name_len = header[i].key.len;

        h->value = header[i].value.data;
        h->value_len = header[i].value.len;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_send_response(ngx_http_request_t *r)
{
    int                        rc;
    ngx_uint_t                 fin;
    ngx_connection_t          *c, *fc;
    ngx_http_v3_connection_t  *h3c;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 send response stream %ui", r->qstream->id);

    fc = r->connection;

    if (fc->error) {
        return NGX_ERROR;
    }

    h3c = r->qstream->connection;
    c = h3c->connection;

    if (r->qstream->headers == NULL) {

        r->qstream->headers =
            ngx_array_create(r->pool, 1, sizeof(quiche_h3_header));

        if (r->qstream->headers == NULL) {
            return NGX_ERROR;
        }

        if (ngx_http_v3_push_response_headers(r, r->qstream->headers) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    fin = r->header_only
          || (r->headers_out.content_length_n == 0 && !r->expect_trailers);

    rc = quiche_h3_send_response(h3c->h3, c->quic->conn, r->qstream->id,
                                 r->qstream->headers->elts,
                                 r->qstream->headers->nelts,
                                 fin);

    if (rc == QUICHE_H3_ERR_STREAM_BLOCKED) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 stream blocked %ui", r->qstream->id);

        r->qstream->blocked = 1;

        fc->write->active = 1;
        fc->write->ready = 0;

        return NGX_AGAIN;
    }

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    if (fin) {
        r->qstream->out_closed = 1;
    }

    r->qstream->headers_sent = 1;

    if (r->done) {
        fc->write->handler = ngx_http_v3_close_stream_handler;
        fc->read->handler = ngx_http_empty_handler;
    }

    ngx_post_event(c->write, &ngx_posted_events);

    return NGX_OK;
}


static ssize_t
ngx_http_v3_stream_do_send(ngx_connection_t *fc, ngx_buf_t *b, ngx_int_t fin)
{
    ssize_t                    n;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_v3_connection_t  *h3c;
    ngx_http_v3_stream_t      *stream;

    uint8_t *buf = b ? b->pos : NULL;
    size_t buf_len = b ? ngx_buf_size(b) : 0;

    r = fc->data;
    stream = r->qstream;
    h3c = stream->connection;
    c = h3c->connection;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, fc->log, 0,
                   "http3 stream %uz to write %uz bytes, fin=%d",
                   stream->id, buf_len, fin);

    if (!stream->headers_sent) {
        return NGX_AGAIN;
    }

    n = quiche_h3_send_body(h3c->h3, c->quic->conn, r->qstream->id,
                            buf, buf_len, fin);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, stream->connection->connection->log, 0,
                   "http3 stream written %z bytes", n);

    if (n == QUICHE_H3_ERR_DONE) {
        return NGX_AGAIN;
    }

    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, fc->log, 0, "stream write failed: %d", n);
        return NGX_ERROR;
    }

    return n;
}


static ngx_chain_t *
ngx_http_v3_send_chain(ngx_connection_t *fc, ngx_chain_t *in, off_t limit)
{
    ssize_t                n, sent;
    off_t                  send, prev_send;
    ngx_uint_t             blocked, fin;

    ngx_http_request_t    *r;
    ngx_http_v3_stream_t  *stream;

    r = fc->data;
    stream = r->qstream;

    send = 0;

    blocked = 0;

    while (in) {
        off_t size = ngx_buf_size(in->buf);

        if (size || in->buf->last_buf) {
            break;
        }

        in = in->next;
    }

    if (in == NULL || stream->out_closed) {
        return NULL;
    }

    while (in) {
        prev_send = send;

        fin = in->buf->last_buf;

        send += ngx_buf_size(in->buf);

        n = ngx_http_v3_stream_do_send(fc, in->buf, fin);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        sent = (n == NGX_AGAIN) ? 0 : n;

        fc->sent += sent;

        in->buf->pos += sent;

        /* Partial (or no) write, end now. */
        if ((n == NGX_AGAIN) || (send - prev_send != sent)) {
            blocked = 1;
            break;
        }

        /* Buffer is fully written, switch to the next. */
        if (in->buf->pos == in->buf->last) {
            in = in->next;
        }

        if (fin) {
            stream->out_closed = 1;
        }
    }

    if (blocked) {
        if (!stream->blocked) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, stream->connection->connection->log, 0,
                           "http3 stream blocked %ui", stream->id);

            stream->blocked = 1;

            fc->write->active = 1;
            fc->write->ready = 0;
        }
    }

    ngx_post_event(stream->connection->connection->write, &ngx_posted_events);

    return in;
}


void
ngx_http_v3_close_stream(ngx_http_v3_stream_t *stream, ngx_int_t rc)
{
    ngx_event_t               *ev;
    ngx_connection_t          *fc;
    ngx_http_v3_connection_t  *h3c;

    h3c = stream->connection;

    fc = stream->request->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, h3c->connection->log, 0,
                   "http3 close stream %ui", stream->id);

    if (stream->blocked) {
        fc->write->handler = ngx_http_v3_close_stream_handler;
        fc->read->handler = ngx_http_empty_handler;
        return;
    }

    quiche_conn_stream_shutdown(h3c->connection->quic->conn, stream->id,
                                QUICHE_SHUTDOWN_READ, 0);

    ngx_rbtree_delete(&h3c->streams, &stream->node);

    fc = stream->request->connection;

    ngx_http_free_request(stream->request, rc);

    ev = fc->read;

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    if (ev->posted) {
        ngx_delete_posted_event(ev);
    }

    ev = fc->write;

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    if (ev->posted) {
        ngx_delete_posted_event(ev);
    }

    fc->data = h3c->free_fake_connections;
    h3c->free_fake_connections = fc;

    h3c->processing--;

    ngx_http_v3_handle_connection(h3c);
}


static void
ngx_http_v3_close_stream_handler(ngx_event_t *ev)
{
    ngx_connection_t    *fc;
    ngx_http_request_t  *r;

    fc = ev->data;
    r = fc->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                   "http3 close stream handler");

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_INFO, fc->log, NGX_ETIMEDOUT, "client timed out");

        fc->timedout = 1;

        ngx_http_v3_close_stream(r->qstream, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    ngx_http_v3_close_stream(r->qstream, 0);
}

void
ngx_http_v3_stop_stream_read(ngx_http_v3_stream_t *stream, ngx_int_t rc)
{
    ngx_http_v3_connection_t  *h3c;

    if (!stream) {
        return;
    }

    h3c = stream->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, h3c->connection->log, 0,
                   "http3 stream shutdown read %ui", stream->id);

    quiche_conn_stream_shutdown(h3c->connection->quic->conn,
                                stream->id,
                                QUICHE_SHUTDOWN_READ, rc);
}


static void
ngx_http_v3_finalize_connection(ngx_http_v3_connection_t *h3c,
    ngx_uint_t status)
{
    ngx_event_t             *ev;
    ngx_connection_t        *c, *fc;
    ngx_rbtree_node_t       *node, *root, *sentinel;
    ngx_http_request_t      *r;
    ngx_http_v3_stream_t    *stream;

    c = h3c->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 finalize connection");

    quiche_conn_close(c->quic->conn, true, status, NULL, 0);

    c->error = 1;

    if (!h3c->processing) {
        ngx_http_close_connection(c);
        return;
    }

    c->read->handler = ngx_http_empty_handler;
    c->write->handler = ngx_http_empty_handler;

    sentinel = h3c->streams.sentinel;

    /* Close all pending streams / requests. */
    for ( ;; ) {
        root = h3c->streams.root;

        if (root == sentinel) {
            break;
        }

        node = ngx_rbtree_min(root, sentinel);

        stream = (ngx_http_v3_stream_t *) node;

        r = stream->request;
        fc = r->connection;

        fc->error = 1;

        if (c->close) {
            fc->close = 1;
        }

        if (stream->blocked) {
            stream->blocked = 0;

            ev = fc->write;
            ev->active = 0;
            ev->ready = 1;

        } else {
            ev = fc->read;
        }

        ev->eof = 1;
        ev->handler(ev);
    }

    if (h3c->processing) {
        return;
    }

    ngx_http_close_connection(c);
}


static void
ngx_http_v3_pool_cleanup(void *data)
{
    ngx_http_v3_connection_t  *h3c = data;

    if (h3c->h3) {
        quiche_h3_conn_free(h3c->h3);

        h3c->h3 = NULL;
    }
}
