
/*
 * Copyright (C) Cloudflare, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_v3_module.h>

#include <quiche.h>


static ngx_int_t ngx_http_v3_add_variables(ngx_conf_t *cf);

static void *ngx_http_v3_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_v3_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_int_t ngx_http_v3_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static void ngx_http_v3_cleanup_ctx(void *data);


static ngx_command_t  ngx_http_v3_commands[] = {

    { ngx_string("http3_max_concurrent_streams"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, concurrent_streams),
      NULL },

    { ngx_string("http3_max_requests"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, max_requests),
      NULL },

    { ngx_string("http3_max_header_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, max_header_size),
      NULL },

    { ngx_string("http3_initial_max_data"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, max_data),
      NULL },

    { ngx_string("http3_initial_max_stream_data"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, max_stream_data),
      NULL },

    { ngx_string("http3_idle_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, idle_timeout),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_v3_module_ctx = {
    ngx_http_v3_add_variables,             /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_v3_create_srv_conf,           /* create server configuration */
    ngx_http_v3_merge_srv_conf,            /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_v3_module = {
    NGX_MODULE_V1,
    &ngx_http_v3_module_ctx,             /* module context */
    ngx_http_v3_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t ngx_http_v3_variables[] = {

    { ngx_string("http3"), NULL,
      ngx_http_v3_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_v3_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_v3_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_v3_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_v3_srv_conf_t  *h3scf;

    h3scf = ngx_pcalloc(cf->pool, sizeof(ngx_http_v3_srv_conf_t));
    if (h3scf == NULL) {
        return NULL;
    }

    h3scf->idle_timeout = NGX_CONF_UNSET_MSEC;
    h3scf->max_data = NGX_CONF_UNSET_SIZE;
    h3scf->max_stream_data = NGX_CONF_UNSET_SIZE;
    h3scf->max_requests = NGX_CONF_UNSET_UINT;
    h3scf->max_header_size = NGX_CONF_UNSET_SIZE;
    h3scf->concurrent_streams = NGX_CONF_UNSET_UINT;

    return h3scf;
}


#if (NGX_DEBUG)
static void
quiche_log(const char *line, void *argp)
{
    ngx_log_t *log = ngx_cycle->log;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "%s", line);
}
#endif


static char *
ngx_http_v3_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_v3_srv_conf_t *prev = parent;
    ngx_http_v3_srv_conf_t *conf = child;

    ngx_pool_cleanup_t  *cln;

    ngx_conf_merge_msec_value(conf->idle_timeout,
                              prev->idle_timeout, 180000);

    ngx_conf_merge_size_value(conf->max_data,
                              prev->max_data, 10485760);

    ngx_conf_merge_size_value(conf->max_stream_data,
                              prev->max_stream_data, 1048576);

    ngx_conf_merge_uint_value(conf->max_requests,
                              prev->max_requests, 1000);

    ngx_conf_merge_size_value(conf->max_header_size,
                              prev->max_header_size, 16384);

    ngx_conf_merge_uint_value(conf->concurrent_streams,
                              prev->concurrent_streams, 128);

    conf->quic.log = cf->log;

#if (NGX_DEBUG)
    /* Enable quiche debug logging. quiche commit ceade4 or later is required */
    quiche_enable_debug_logging(quiche_log, NULL);
#endif

    if (ngx_quic_create_conf(&conf->quic) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    quiche_config_set_max_idle_timeout(conf->quic.config, conf->idle_timeout);

    quiche_config_set_initial_max_data(conf->quic.config, conf->max_data);

    quiche_config_set_initial_max_stream_data_bidi_remote(conf->quic.config,
                                                          conf->max_stream_data);

    quiche_config_set_initial_max_stream_data_uni(conf->quic.config,
                                                  conf->max_stream_data);

    quiche_config_set_initial_max_streams_bidi(conf->quic.config,
                                               conf->concurrent_streams);

    /* For HTTP/3 we only need 3 unidirectional streams. */
    quiche_config_set_initial_max_streams_uni(conf->quic.config, 3);

    conf->http3 = quiche_h3_config_new();
    if (conf->http3 == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "failed to create HTTP/3 config");
        return NGX_CONF_ERROR;
    }

    quiche_h3_config_set_max_header_list_size(conf->http3,
                                              conf->max_header_size);

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_quic_cleanup_ctx;
    cln->data = &conf->quic;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_http_v3_cleanup_ctx;
    cln->data = conf->http3;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_v3_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_connection_t   *c;

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    c = r->connection;
    if (c == NULL) {
        return NGX_ERROR;
    }

    if (c->quic != NULL) {
        v->len = sizeof("h3") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "h3";

        return NGX_OK;
    }

    *v = ngx_http_variable_null_value;
    return NGX_OK;
}


static void
ngx_http_v3_cleanup_ctx(void *data)
{
    quiche_h3_config  *config = data;

    quiche_h3_config_free(config);
}
