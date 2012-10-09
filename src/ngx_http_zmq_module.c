/*
 * Copyright (C) 2010-2011 Alvaro Saurin
 * Copyright (C)           chaoslawful
 * Copyright (C)           agentzh
 * Copyright (C) 2002-2010 Igor Sysoev
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */



#define DDEBUG 1
#include "ngx_http_zmq_debug.h"

#include "ngx_http_zmq_module.h"
#include "ngx_http_zmq_handler.h"
#include "ngx_http_upstream_zmq.h"


/* Forward declaration */

static ngx_int_t ngx_http_zmq_init(ngx_conf_t *cf);

static void * ngx_http_zmq_create_main_conf(ngx_conf_t *cf);

static char * ngx_http_zmq_msg(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char * ngx_http_zmq_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void * ngx_http_zmq_create_loc_conf(ngx_conf_t *cf);

static char * ngx_http_zmq_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_zmq_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_zmq_tid_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);




static ngx_http_variable_t ngx_http_zmq_variables[] = {

    { ngx_string("zmq_thread_id"), NULL,
      ngx_http_zmq_tid_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


/* config directives for module drizzle */
static ngx_command_t ngx_http_zmq_cmds[] = {
    {
      ngx_string("zmq_endpoint"),
      NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
      ngx_http_upstream_zmq_endpoint,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },
    {
      ngx_string("zmq_msg"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_1MORE,
      ngx_http_zmq_msg,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    {
      ngx_string("zmq_pass"),
      NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
      ngx_http_zmq_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    {
      ngx_string("zmq_connect_timeout"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zmq_loc_conf_t, upstream.connect_timeout),
      NULL },
    {
      ngx_string("zmq_timeout"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zmq_loc_conf_t, upstream.send_timeout),
      NULL },
    {
      ngx_string("zmq_buffer_size"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zmq_loc_conf_t, buf_size),
      NULL },

    ngx_null_command
};


/* Nginx HTTP subsystem module hooks */
static ngx_http_module_t ngx_http_zmq_module_ctx = {
    NULL,                                          /* preconfiguration */
    ngx_http_zmq_init,                             /* postconfiguration */

    ngx_http_zmq_create_main_conf,                 /* create_main_conf */
    NULL,                                          /* merge_main_conf */

    ngx_http_upstream_zmq_create_srv_conf,         /* create_srv_conf */
    NULL,                                          /* merge_srv_conf */

    ngx_http_zmq_create_loc_conf,                  /* create_loc_conf */
    ngx_http_zmq_merge_loc_conf                    /* merge_loc_conf */
};


ngx_module_t ngx_http_zmq_module = {
    NGX_MODULE_V1,
    &ngx_http_zmq_module_ctx,             /* module context */
    ngx_http_zmq_cmds,                    /* module directives */
    NGX_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    NULL,                                 /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_zmq_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_zmq_loc_conf_t             *loc_conf;

    loc_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_zmq_loc_conf_t));
    if (loc_conf == NULL) {
        return NULL;
    } else {
        loc_conf->upstream.connect_timeout      = NGX_CONF_UNSET_MSEC;
        loc_conf->upstream.send_timeout         = NGX_CONF_UNSET_MSEC;

        /* the hardcoded values */
        loc_conf->upstream.cyclic_temp_file     = 0;
        loc_conf->upstream.buffering            = 0;
        loc_conf->upstream.ignore_client_abort  = 0;
        loc_conf->upstream.send_lowat           = 0;
        loc_conf->upstream.bufs.num             = 0;
        loc_conf->upstream.busy_buffers_size    = 0;
        loc_conf->upstream.max_temp_file_size   = 0;
        loc_conf->upstream.temp_file_write_size = 0;
        loc_conf->upstream.intercept_errors     = 1;
        loc_conf->upstream.intercept_404        = 1;
        loc_conf->upstream.pass_request_headers = 0;
        loc_conf->upstream.pass_request_body    = 0;

        loc_conf->complex_target                = NGX_CONF_UNSET_PTR;
        loc_conf->buf_size                      = NGX_CONF_UNSET_SIZE;

        loc_conf->main_conf                     = ngx_http_conf_get_module_main_conf(cf, ngx_http_zmq_module);

        return loc_conf;
    }
}


static char *
ngx_http_zmq_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_zmq_loc_conf_t *prev = parent;
    ngx_http_zmq_loc_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    if (conf->zmsgs == NULL) {
        conf->zmsgs         = prev->zmsgs;
    }

    ngx_conf_merge_size_value(conf->buf_size, prev->buf_size, (size_t) ngx_pagesize);

    return NGX_CONF_OK;
}



static void *
ngx_http_zmq_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_zmq_main_conf_t  *main_conf;

    main_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_zmq_main_conf_t));
    if (main_conf == NULL) {
        return NULL;
    }

    main_conf->zcontext = NULL;

    return main_conf;
}

static ngx_int_t
ngx_http_zmq_init(ngx_conf_t *cf)
{
//    ngx_http_zmq_main_conf_t   *main_conf;
    int                         major, minor, patch;


    zmq_version(&major, &minor, &patch);

    zmq_debug(cf->log, "zeromq version %d.%d.%d: creating zmq context", major, minor, patch);

    return NGX_OK;
}

char *
ngx_http_zmq_msg(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                         *value = cf->args->elts;
    ngx_http_zmq_loc_conf_t           *dlcf = conf;
    ngx_http_compile_complex_value_t   ccv;
    ngx_uint_t                         methods;
    ngx_zmq_mixed_t                   *msg;
    ngx_str_t                          msg_str;

    msg     = NULL;
    msg_str = value[cf->args->nelts - 1];

    if (msg_str.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "zmq: empty value in \"%V\" directive", &cmd->name);
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 2) {
        /* default query */
        zmq_debug(cf->log, "default query");

        if (dlcf->zmsg != NULL) {
            return "is duplicate";
        }

        dlcf->zmsg = ngx_pcalloc(cf->pool, sizeof(ngx_zmq_mixed_t));
        if (dlcf->zmsg == NULL) {
            return NGX_CONF_ERROR;
        }

        methods = 0xFFFF;
        msg = dlcf->zmsg;
    }

    if (ngx_http_script_variables_count(&msg_str)) {
        /* complex value */
        zmq_debug(cf->log, "complex value");

        msg->key = methods;

        msg->cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (msg->cv == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf             = cf;
        ccv.value          = &msg_str;
        ccv.complex_value  = msg->cv;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    } else {
        /* simple value */
        zmq_debug(cf->log, "simple value");

        msg->key  = methods;
        msg->sv   = msg_str;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_zmq_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_zmq_loc_conf_t                 * dlcf = conf;
    ngx_http_core_loc_conf_t                * clcf;
    ngx_str_t                               * value;
    ngx_http_compile_complex_value_t          ccv;
    ngx_url_t                                 url;
    ngx_uint_t                                n;

    if (dlcf->upstream.upstream) {
        return "is duplicate";
    }

    if (ngx_http_zmq_add_variables(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_zmq_handler;

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    value = cf->args->elts;

    n = ngx_http_script_variables_count(&value[1]);
    if (n) {
        dlcf->complex_target = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (dlcf->complex_target == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
        ccv.cf            = cf;
        ccv.value         = &value[1];
        ccv.complex_value = dlcf->complex_target;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    dlcf->complex_target = NULL;

    ngx_memzero(&url, sizeof(ngx_url_t));

    url.url        = value[1];
    url.no_resolve = 1;

    dlcf->upstream.upstream = ngx_http_upstream_add(cf, &url, 0);

    if (dlcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_zmq_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_zmq_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_zmq_tid_variable(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data)
{
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->len = 0;
    v->data = (u_char *) "";

    return NGX_OK;
}

