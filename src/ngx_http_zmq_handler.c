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
#include "ngx_http_zmq_processor.h"
#include "ngx_http_zmq_util.h"
#include "ngx_http_upstream_zmq.h"

/* for read/write event handlers */


static ngx_int_t   ngx_http_zmq_create_request    (ngx_http_request_t *r);
static ngx_int_t   ngx_http_zmq_reinit_request    (ngx_http_request_t *r);
static void        ngx_http_zmq_abort_request     (ngx_http_request_t *r);
static void        ngx_http_zmq_finalize_request  (ngx_http_request_t *r, ngx_int_t rc);

static ngx_int_t   ngx_http_zmq_process_header    (ngx_http_request_t *r);

static ngx_int_t   ngx_http_zmq_input_filter_init (void *data);
static ngx_int_t   ngx_http_zmq_input_filter      (void *data, ssize_t bytes);




ngx_int_t
ngx_http_zmq_handler(ngx_http_request_t *r)
{
    ngx_http_upstream_t            *u;
    ngx_http_zmq_loc_conf_t    *dlcf;
#if defined(nginx_version) && nginx_version < 8017
    ngx_http_zmq_ctx_t         *dctx;
#endif
    ngx_str_t                       target;
    ngx_url_t                       url;
    ngx_connection_t               *c;

    if (r->subrequest_in_memory) {
        /* TODO: add support for subrequest in memory by emitting output into u->buffer instead */

        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_http_zmq_module does not support subrequest in memory");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_zmq_module);

#if defined(nginx_version) && \
    ((nginx_version >= 7063 && nginx_version < 8000) \
     || nginx_version >= 8007)

    zmq_debug(r->connection->log, "creating upstream.......");
    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

#else /* 0.7.x < 0.7.63, 0.8.x < 0.8.7 */

    dd("XXX create upstream");
    u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
    if (u == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->peer.log = r->connection->log;
    u->peer.log_error = NGX_ERROR_ERR;
#  if (NGX_THREADS)
    u->peer.lock = &r->connection->lock;
#  endif

    r->upstream = u;

#endif

    if (dlcf->complex_target) {
        /* variables used in the zmq_pass directive */
        if (ngx_http_complex_value(r, dlcf->complex_target, &target)
                != NGX_OK)
        {
            zmq_debug(r->connection->log, "failed to compile");
            return NGX_ERROR;
        }

        if (target.len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "zmq: handler: empty \"zmq_pass\" target");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        url.host = target;
        url.port = 0;
        url.no_resolve = 1;

        dlcf->upstream.upstream = ngx_http_upstream_zmq_add(r, &url);

        if (dlcf->upstream.upstream == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "zmq: upstream \"%V\" not found", &target);

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

#if defined(nginx_version) && nginx_version < 8017
    dctx = ngx_pcalloc(r->pool, sizeof(ngx_http_zmq_ctx_t));
    if (dctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, dctx, ngx_http_zmq_module);
#endif

    u->schema.len = sizeof("zmq://") - 1;
    u->schema.data = (u_char *) "zmq://";

    u->output.tag = (ngx_buf_tag_t) &ngx_http_zmq_module;

    zmq_debug(r->connection->log, "zmq tag: %p", (void *) u->output.tag);

    u->conf = &dlcf->upstream;

    u->create_request    = ngx_http_zmq_create_request;
    u->reinit_request    = ngx_http_zmq_reinit_request;
    u->process_header    = ngx_http_zmq_process_header;
    u->abort_request     = ngx_http_zmq_abort_request;
    u->finalize_request  = ngx_http_zmq_finalize_request;

    /* we bypass the upstream input filter mechanism in ngx_http_upstream_process_headers */
    u->input_filter_init  = ngx_http_zmq_input_filter_init;
    u->input_filter       = ngx_http_zmq_input_filter;
    u->input_filter_ctx   = NULL;

#if defined(nginx_version) && nginx_version >= 8011
    r->main->count++;
#endif

    ngx_http_upstream_zsock_init(r);

    /* override the read/write event handler to our own */
    u->write_event_handler = ngx_http_zmq_wev_handler;
    u->read_event_handler  = ngx_http_zmq_rev_handler;

    /* a bit hack-ish way to return error response (clean-up part) */
    if ((u->peer.connection) && (u->peer.connection->fd == 0)) {
        c = u->peer.connection;
        u->peer.connection = NULL;

        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        ngx_free_connection(c);

        ngx_http_upstream_zmq_finalize_request(r, u,
#if defined(nginx_version) && (nginx_version >= 8017)
            NGX_HTTP_SERVICE_UNAVAILABLE);
#else
            dctx->status ? dctx->status : NGX_HTTP_INTERNAL_SERVER_ERROR);
#endif
    }

    return NGX_DONE;
}


void
ngx_http_zmq_wev_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_connection_t            *c;

    zmq_debug(r->connection->log, "write-handler");

    /* just to ensure u->reinit_request always gets called for upstream_next */
    u->request_sent = 1;

    c = u->peer.connection;

//    if (c->write->timedout) {
//        zmq_debug(r->connection->log, "zmq connection write timeout");
//        return;
//    }

    (void) ngx_http_zmq_process_events(r);
}


void
ngx_http_zmq_rev_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_connection_t            *c;

    zmq_debug(r->connection->log, "read-handler");

    /* just to ensure u->reinit_request always gets called for upstream_next */
    u->request_sent = 1;

    c = u->peer.connection;

//    if (c->read->timedout) {
//        zmq_debug(r->connection->log, "zmq connection read timeout");
//        return;
//    }

    (void) ngx_http_zmq_process_events(r);
}


static ngx_int_t
ngx_http_zmq_create_request(ngx_http_request_t *r)
{
    r->upstream->request_bufs = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_zmq_reinit_request(ngx_http_request_t *r)
{
    ngx_http_upstream_t         *u;

    u = r->upstream;

    /* override the read/write event handler to our own */
    u->write_event_handler = ngx_http_zmq_wev_handler;
    u->read_event_handler  = ngx_http_zmq_rev_handler;

    return NGX_OK;
}


static void
ngx_http_zmq_abort_request(ngx_http_request_t *r)
{
}


static void
ngx_http_zmq_finalize_request(ngx_http_request_t *r,
        ngx_int_t rc)
{
}


static ngx_int_t
ngx_http_zmq_process_header(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
           "ngx_http_zmq_process_header should not be called"
           " by the upstream");

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_zmq_input_filter_init(void *data)
{
    ngx_http_request_t          *r = data;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
           "ngx_http_zmq_input_filter_init should not be called"
           " by the upstream");

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_zmq_input_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t          *r = data;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
           "ngx_http_zmq_input_filter should not be called"
           " by the upstream");

    return NGX_ERROR;
}

