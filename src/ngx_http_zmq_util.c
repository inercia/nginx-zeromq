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
#include "ngx_http_zmq_util.h"
#include "ngx_http_zmq_handler.h"
#include "ngx_http_zmq_processor.h"

#include <ngx_core.h>
#include <ngx_http.h>


//static ngx_int_t ngx_http_upstream_zsock_reinit(ngx_http_request_t *r, ngx_http_upstream_t *u);

static void ngx_http_upstream_zsock_handler(ngx_event_t *ev);

static void ngx_http_upstream_zsock_connect(ngx_http_request_t *r, ngx_http_upstream_t *u);

static void ngx_http_upstream_zsock_cleanup(void *data);


/* the following functions are copied directly from
   ngx_http_upstream.c in nginx 0.8.30, just because
   they're static. sigh. */

void
ngx_http_upstream_zmq_finalize_request(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t rc)
{
    ngx_time_t  *tp;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "finalizing request: %i", rc);

    if (u->cleanup) {
        *u->cleanup = NULL;
    }

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    if (u->state && u->state->response_sec) {
        tp = ngx_timeofday();
        u->state->response_sec   = tp->sec  - u->state->response_sec;
        u->state->response_msec  = tp->msec - u->state->response_msec;

        if (u->pipe) {
            u->state->response_length = u->pipe->read_length;
        }
    }

    if (u->finalize_request) {
        u->finalize_request(r, rc);
    }

//    if (u->peer.free) {
//        zmq_debug(r->connection->log, "starting to free peer");
//        u->peer.free(&u->peer, u->peer.data, 0);
//        zmq_debug(r->connection->log, "peer freed");
//    }
//
//    zmq_debug(r->connection->log, "calling ngx_close_connection()");
//    if (u->peer.connection) {
//        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "closing upstream connection: %d", u->peer.connection->fd);
//        ngx_close_connection(u->peer.connection);
//    }
//
//    u->peer.connection = NULL;
//
//    if (u->pipe && u->pipe->temp_file) {
//        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "zeromq upstream temp fd: %d", u->pipe->temp_file->file.fd);
//    }

#if (NGX_HTTP_CACHE)
    if (u->cacheable && r->cache) {
        time_t  valid;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream cache fd: %d",
                       r->cache->file.fd);

        if (rc == NGX_HTTP_BAD_GATEWAY || rc == NGX_HTTP_GATEWAY_TIME_OUT) {

            valid = ngx_http_file_cache_valid(u->conf->cache_valid, rc);

            if (valid) {
                r->cache->valid_sec = ngx_time() + valid;
                r->cache->error = rc;
            }
        }

# if defined(nginx_version) && (nginx_version >= 8047)
        ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
# else
        ngx_http_file_cache_free(r, u->pipe->temp_file);
# endif
    }

#endif

    if (u->header_sent && (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE))  {
        rc = 0;
    }

    if (rc == NGX_DECLINED) {
        return;
    }

    r->connection->log->action = "sending to client";

    if (rc == 0) {
        rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    ngx_http_finalize_request(r, rc);
}



ngx_int_t
ngx_http_upstream_zmq_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof) {
            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, c->write->kq_errno,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_errno;
        }

        if (err) {
            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


void
ngx_http_upstream_zsock_init(ngx_http_request_t *r)
{
    ngx_connection_t     *c;

    c = r->connection;

    zmq_debug(c->log, "initializing zsocket, client timer: %d", c->read->timer_set);

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        if (!c->write->active) {
            if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) == NGX_ERROR) {
                zmq_debug(c->log, "finalizing request");
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
    }

    ngx_http_upstream_zsock_init_request(r);
}


void
ngx_http_upstream_zsock_init_request(ngx_http_request_t *r)
{
//    ngx_str_t                      *host;
//    ngx_uint_t                      i;
//    ngx_resolver_ctx_t             *ctx, temp;
    ngx_http_cleanup_t             *cln;
    ngx_http_upstream_t            *u;
    ngx_http_core_loc_conf_t       *clcf;
    ngx_http_upstream_srv_conf_t   *uscf;
//    ngx_http_upstream_srv_conf_t   **uscfp;
//    ngx_http_upstream_main_conf_t  *umcf;

#if defined(nginx_version) && nginx_version >= 8011
    if (r->aio) {
        return;
    }
#endif

    zmq_debug(r->connection->log, "initilizing zsocket request");

    u = r->upstream;

    u->store = (u->conf->store || u->conf->store_lengths);

//    if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
//        r->read_event_handler   = ngx_http_upstream_zsock_rd_check_broken_connection;
//        r->write_event_handler  = ngx_http_upstream_zsock_wr_check_broken_connection;
//    }

    if (r->request_body) {
        u->request_bufs = r->request_body->bufs;
    }

    if (u->create_request(r) != NGX_OK) {
        zmq_debug(r->connection->log, "finalizing request due to errorn when create_request");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

#if defined(nginx_version) && nginx_version >= 8022
    u->peer.local = u->conf->local;
#endif

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

#if defined(nginx_version) && nginx_version >= 8011
    u->output.alignment = clcf->directio_alignment;
#endif

    u->output.pool           = r->pool;
    u->output.bufs.num       = 1;
    u->output.bufs.size      = clcf->client_body_buffer_size;
    u->output.output_filter  = ngx_chain_writer;
    u->output.filter_ctx     = &u->writer;

    u->writer.pool = r->pool;

    if (r->upstream_states == NULL) {
        r->upstream_states = ngx_array_create(r->pool, 1, sizeof(ngx_http_upstream_state_t));
        if (r->upstream_states == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    } else {
        u->state = ngx_array_push(r->upstream_states);
        if (u->state == NULL) {
            ngx_http_upstream_zmq_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        ngx_memzero (u->state, sizeof(ngx_http_upstream_state_t));
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        zmq_debug(r->connection->log, "finalizing request due to error when cleanup_add");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    cln->handler = ngx_http_upstream_zsock_cleanup;
    cln->data = r;
    u->cleanup = &cln->handler;

    uscf = u->conf->upstream;

//    if (uscf->peer.init(r, uscf) != NGX_OK) {
//        ngx_http_upstream_zmq_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
//        return;
//    }

    zmq_debug(r->connection->log, "initializing peer");
    uscf->peer.init(r, uscf);

    ngx_http_upstream_zsock_connect(r, u);
}


static void
ngx_http_upstream_zsock_connect(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t          rc;
    ngx_time_t        *tp;
    ngx_connection_t  *c;

    r->connection->log->action         = "connecting zeromq socket";
    r->connection->single_connection   = 0;

    if (u->state && u->state->response_sec) {
        tp = ngx_timeofday();
        u->state->response_sec   = tp->sec  - u->state->response_sec;
        u->state->response_msec  = tp->msec - u->state->response_msec;
    }

    u->state = ngx_array_push(r->upstream_states);
    if (u->state == NULL) {
        ngx_http_upstream_zmq_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(u->state, sizeof(ngx_http_upstream_state_t));

    tp = ngx_timeofday();
    u->state->response_sec  = tp->sec;
    u->state->response_msec = tp->msec;

    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "zsocket connect: %i", rc);

    u->state->peer = u->peer.name;

    c = u->peer.connection;

    c->data = r;

    c->write->handler       = ngx_http_upstream_zsock_handler;
    c->read->handler        = ngx_http_upstream_zsock_handler;
    u->write_event_handler  = ngx_http_zmq_wev_handler;
    u->read_event_handler   = ngx_http_zmq_rev_handler;

    c->sendfile          &= r->connection->sendfile;
    u->output.sendfile    = c->sendfile;

    c->pool       = r->pool;
    c->log        = r->connection->log;
    c->read->log  = c->log;
    c->write->log = c->log;

    /* init or reinit the ngx_output_chain() and ngx_chain_writer() contexts */

    u->writer.out        = NULL;
    u->writer.last       = &u->writer.out;
    u->writer.connection = c;
    u->writer.limit      = 0;

    u->request_sent = 0;

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, u->conf->connect_timeout);
        return;
    }

    (void) ngx_http_zmq_process_events(r);
}

static void
ngx_http_upstream_zsock_cleanup(void *data)
{
    ngx_http_request_t *r = data;

    ngx_http_upstream_t  *u;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "cleanup zeromq socket request: \"%V\"", &r->uri);

    u = r->upstream;

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    ngx_http_upstream_zmq_finalize_request(r, u, NGX_DONE);
}


static void
ngx_http_upstream_zsock_handler(ngx_event_t *ev)
{
    ngx_connection_t     *c;
    ngx_http_request_t   *r;
    ngx_http_log_ctx_t   *ctx;
    ngx_http_upstream_t  *u;

    c = ev->data;
    r = c->data;

    u = r->upstream;
    c = r->connection;

    ctx = c->log->data;
    ctx->current_request = r;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "zsocket upstream request: \"%V?%V\"", &r->uri, &r->args);

    if (ev->write) {
        u->write_event_handler(r, u);
    } else {
        u->read_event_handler(r, u);
    }

    ngx_http_run_posted_requests(c);
}

