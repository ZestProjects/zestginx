
/*
 * Copyright (C) Cloudflare, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/* Limit outgoing packets to 1200 bytes. This is the minimum value allowed. */
#define MAX_DATAGRAM_SIZE 1200

/* errors */
#define NGX_QUIC_NO_ERROR  0x0
#define NGX_QUIC_INTERNAL_ERROR  0x1


static void ngx_quic_read_handler(ngx_event_t *ev);
static void ngx_quic_write_handler(ngx_event_t *ev);

static void ngx_quic_handshake_completed(ngx_connection_t *c);

static void ngx_quic_shutdown_handler(ngx_event_t *ev);

static void ngx_quic_finalize_connection(ngx_connection_t *c, ngx_uint_t status);
static void ngx_quic_close_connection(ngx_connection_t *c);

static ngx_int_t ngx_quic_send_udp_packet(ngx_connection_t *c, uint8_t *buf,
    size_t len);


static ngx_command_t  ngx_quic_commands[] = {

    ngx_null_command
};


static ngx_core_module_t  ngx_quic_module_ctx = {
    ngx_string("quic"),
    NULL,
    NULL
};


ngx_module_t  ngx_quic_module = {
    NGX_MODULE_V1,
    &ngx_quic_module_ctx,                  /* module context */
    ngx_quic_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_quic_create_conf(ngx_quic_t *quic)
{
    quic->config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    if (quic->config == NULL) {
        ngx_log_error(NGX_LOG_EMERG, quic->log, 0, "failed to create quic config");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_validate_initial(ngx_event_t *ev, u_char *buf, ssize_t buf_len)
{
    /* Check incoming packet type, if it's not Initial we shouldn't be here. */
    if (((buf[0] & 0x30) >> 4) != 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "packet is not quic client initial");
        return NGX_ERROR;
    }

    /* Client Initial packets must be at least 1200 bytes. */
    if (buf_len < QUICHE_MIN_CLIENT_INITIAL_LEN) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "quic initial packet is too short");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_create_connection(ngx_quic_t *quic, ngx_connection_t *c)
{
    int                     rc;
    u_char                 *buf;
    size_t                  buf_len;
    quiche_conn            *conn;
    static uint8_t          out[MAX_DATAGRAM_SIZE];

    uint8_t                 pkt_type;
    uint32_t                pkt_version;

    uint8_t                 scid[QUICHE_MAX_CONN_ID_LEN];
    size_t                  scid_len = sizeof(scid);

    uint8_t                 dcid[QUICHE_MAX_CONN_ID_LEN];
    size_t                  dcid_len = sizeof(dcid);

    uint8_t                 token[1];
    size_t                  token_len = sizeof(token);

    ngx_quic_connection_t  *qc;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic init connection");

    /* Extract some fields from the client's Initial packet, which was saved
     * into c->buffer by ngx_event_recvmsg(). */
    buf = c->buffer->pos;
    buf_len = ngx_buf_size(c->buffer);

    rc = quiche_header_info(buf, buf_len, QUICHE_MAX_CONN_ID_LEN,
                            &pkt_version, &pkt_type,
                            scid, &scid_len, dcid, &dcid_len,
                            token, &token_len);
    if (rc < 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "failed to parse quic header: %d", rc);
        return NGX_ERROR;
    }

    /* Version mismatch, do version negotiation. */
    if (!quiche_version_is_supported(pkt_version)) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic version negotiation");

        ssize_t written = quiche_negotiate_version(scid, scid_len,
                                                   dcid, dcid_len,
                                                   out, sizeof(out));

        if (written < 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                          "failed to create quic vneg packet: %d", written);
            return NGX_ERROR;
        }

        if (ngx_quic_send_udp_packet(c, out, written) == NGX_ERROR) {
            return NGX_ERROR;
        }

        return NGX_DONE;
    }

    /* Initialize source connection ID with some random bytes. */
    RAND_bytes(scid, sizeof(scid));

#if (NGX_DEBUG)
    {
    uint8_t dcid_hex[QUICHE_MAX_CONN_ID_LEN * 2],
            scid_hex[QUICHE_MAX_CONN_ID_LEN * 2];

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
        "new quic connection dcid:%*.s new_scid:%*.s",
        ngx_hex_dump(dcid_hex, dcid, dcid_len) - dcid_hex, dcid_hex,
        ngx_hex_dump(scid_hex, scid, scid_len) - scid_hex, scid_hex);
    }
#endif

    conn = quiche_conn_new_with_tls(scid, sizeof(scid), NULL, 0, quic->config,
                                    c->ssl->connection, true);
    if (conn == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to create quic connection");
        return NGX_ERROR;
    }

    qc = ngx_pcalloc(c->pool, sizeof(ngx_quic_connection_t));
    if (qc == NULL) {
        return NGX_ERROR;
    }

    qc->handler = NULL;

    qc->conn = conn;

    c->quic = qc;

    return NGX_OK;
}


ngx_int_t
ngx_quic_handshake(ngx_connection_t *c)
{
    u_char   *buf;
    size_t    buf_len;
    ssize_t   done;

    /* Process the client's Initial packet, which was saved into c->buffer by
     * ngx_event_recvmsg(). */
    buf = c->buffer->pos;
    buf_len = ngx_buf_size(c->buffer);

    done = quiche_conn_recv(c->quic->conn, buf, buf_len);

    if ((done < 0) && (done != QUICHE_ERR_DONE)) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                      "failed to process quic packet: %d", done);
        return NGX_ERROR;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    c->read->handler = ngx_quic_read_handler;
    c->write->handler = ngx_quic_write_handler;

    ngx_post_event(c->write, &ngx_posted_events);

    return NGX_AGAIN;
}


static void
ngx_quic_read_handler(ngx_event_t *rev)
{
    int                n;
    static uint8_t     buf[65535];
    ngx_connection_t  *c;

    c = rev->data;

    c->log->action = "reading QUIC packets";

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic read handler");

    if (rev->timedout) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic connection timed out");

        ngx_quic_finalize_connection(c, NGX_QUIC_INTERNAL_ERROR);
        return;
    }

    for (;;) {
        n = c->recv(c, buf, sizeof(buf));
        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR) {
            ngx_quic_finalize_connection(c, NGX_QUIC_INTERNAL_ERROR);
            return;
        }

        ssize_t done = quiche_conn_recv(c->quic->conn, buf, n);

        if (done == QUICHE_ERR_DONE) {
            break;
        }

        if (done < 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "failed to process quic packet: %d", done);

            ngx_quic_finalize_connection(c, NGX_QUIC_INTERNAL_ERROR);
            return;
        }
    }

    if (quiche_conn_is_in_early_data(c->quic->conn) ||
            quiche_conn_is_established(c->quic->conn)) {
        if (!c->ssl->handshaked) {
            ngx_quic_handshake_completed(c);
        }

        if ((c->quic == NULL) || (c->quic->handler == NULL)) {
            return;
        }

        /* Notify application layer that there might be stream data to read. */
        c->quic->handler(c);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic done reading");

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_quic_finalize_connection(c, NGX_QUIC_INTERNAL_ERROR);
        return;
    }

    ngx_post_event(c->write, &ngx_posted_events);
}


static void
ngx_quic_write_handler(ngx_event_t *wev)
{
    ngx_connection_t   *c;
    ngx_msec_t          expiry;
    static uint8_t      out[MAX_DATAGRAM_SIZE];

    c = wev->data;

    c->log->action = "writing QUIC packets";

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic write handler");

    if (wev->timedout) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic alarm fired");

        quiche_conn_on_timeout(c->quic->conn);
    }

    if (quiche_conn_is_closed(c->quic->conn)) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic connection is closed");

        ngx_quic_finalize_connection(c, NGX_QUIC_NO_ERROR);
        return;
    }

    for (;;) {
        ssize_t written = quiche_conn_send(c->quic->conn, out, sizeof(out));

        if (written == QUICHE_ERR_DONE) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic done writing");
            break;
        }

        if (written < 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "failed to create quic packet: %d", written);

            ngx_quic_finalize_connection(c, NGX_QUIC_INTERNAL_ERROR);
            return;
        }

        if (ngx_quic_send_udp_packet(c, out, written) == NGX_ERROR) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "failed to send quic packet");

            ngx_quic_finalize_connection(c, NGX_QUIC_INTERNAL_ERROR);
            return;
        }
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_quic_finalize_connection(c, NGX_QUIC_INTERNAL_ERROR);
        return;
    }

    expiry = quiche_conn_timeout_as_millis(c->quic->conn);
    expiry = ngx_max(expiry, 1);

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    /* quiche_conn_timeout_as_millis() will return UINT64_MAX when the timer
     * should be unset (this would be equvalent to returning Option::None in
     * Rust). To avoid overflow we need to explicitly check for this value. */
    if (expiry != UINT64_MAX) {
        ngx_add_timer(wev, expiry);
    }
}


static void
ngx_quic_handshake_completed(ngx_connection_t *c)
{
#if (NGX_DEBUG)
    {
    char         buf[129], *s, *d;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    const
#endif
    SSL_CIPHER  *cipher;

    cipher = SSL_get_current_cipher(c->ssl->connection);

    if (cipher) {
        SSL_CIPHER_description(cipher, &buf[1], 128);

        for (s = &buf[1], d = buf; *s; s++) {
            if (*s == ' ' && *d == ' ') {
                continue;
            }

            if (*s == LF || *s == CR) {
                continue;
            }

            *++d = *s;
        }

        if (*d != ' ') {
            d++;
        }

        *d = '\0';

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "QUIC: %s, cipher: \"%s\"",
                       SSL_get_version(c->ssl->connection), &buf[1]);

        if (SSL_session_reused(c->ssl->connection)) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic reused session");
        }

    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic no shared ciphers");
    }
    }
#endif

    ngx_del_timer(c->read);

    c->ssl->handshaked = 1;

    /* Notify application layer that the handshake is complete. */
    c->ssl->handler(c);
}


ngx_int_t
ngx_quic_shutdown(ngx_connection_t *c)
{
    if (!quiche_conn_is_closed(c->quic->conn)) {
        /* We shouldn't free the connection state yet, as we need to wait for
         * the draining timeout to expire. Setup event handlers such that we
         * will try again when that happens (or when another event is
         * triggered). */
        c->read->handler = ngx_quic_shutdown_handler;
        c->write->handler = ngx_quic_shutdown_handler;

        /* We need to flush any remaining frames to the client (including
         * CONNECTION_CLOSE), so invoke the write handler. This also takes
         * care of setting up the draining timer. */
        ngx_quic_write_handler(c->write);

        /* The QUIC connection might have already been freed inside the write
         * handler, in which case we are done. */
        if (c->destroyed) {
            return NGX_OK;
        }

        return NGX_AGAIN;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "free quic connection");

    quiche_conn_free(c->quic->conn);

    c->quic = NULL;
    c->ssl = NULL;

    return NGX_OK;
}


static void
ngx_quic_shutdown_handler(ngx_event_t *ev)
{
    ngx_connection_t           *c;
    ngx_connection_handler_pt   handler;

    c = ev->data;
    handler = c->quic->handler;

    if (ev->timedout) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic alarm fired");

        quiche_conn_on_timeout(c->quic->conn);

        ev->timedout = 0;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "quic shutdown handler");

    if (ngx_quic_shutdown(c) == NGX_AGAIN) {
        return;
    }

    handler(c);
}


static void
ngx_quic_finalize_connection(ngx_connection_t *c, ngx_uint_t status)
{
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "finalize quic connection: %d", c->fd);

    c->error = 1;

    if (quiche_conn_is_closed(c->quic->conn)) {
        c->close = 1;
    }

    quiche_conn_close(c->quic->conn, false, status, NULL, 0);

    /* Notify the application layer that the connection is in an error
     * state and will be closed. */
    if (c->quic->handler != NULL) {
        c->quic->handler(c);
        return;
    }

    ngx_quic_close_connection(c);
}


static void
ngx_quic_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "close quic connection: %d", c->fd);

    if (c->quic) {
        if (ngx_quic_shutdown(c) == NGX_AGAIN) {
            c->quic->handler = ngx_quic_close_connection;
            return;
        }

        if (c->destroyed) {
            return;
        }
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


void
ngx_quic_cleanup_ctx(void *data)
{
    ngx_quic_t  *quic = data;

    quiche_config_free(quic->config);
}


static ngx_int_t
ngx_quic_send_udp_packet(ngx_connection_t *c, uint8_t *buf, size_t len)
{
    ngx_buf_t    out_buf = {0};
    ngx_chain_t  out_chain = {0};

    /* The send_chain() API takes an ngx_chain_t parameter instead of a simple
     * buffer, so we need to initialize the chain such that it contains only a
     * single buffer.
     *
     * The c->send_chain() call is required (instead of just c->send()) because
     * it uses the sendmsg(2) syscall (instead of sendto(2)), which allows us to
     * specify the correct source IP address for the connection. */

    out_buf.start = out_buf.pos = buf;
    out_buf.end = out_buf.last = buf + len;
    out_buf.memory = 1;
    out_buf.flush = 1;

    out_chain.buf = &out_buf;
    out_chain.next = NULL;

    if (c->send_chain(c, &out_chain, 0) == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
