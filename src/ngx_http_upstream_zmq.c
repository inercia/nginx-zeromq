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
#include "ngx_http_upstream_zmq.h"
#include "ngx_http_zmq_processor.h"
#include "ngx_http_zmq_util.h"

#include "assert.h"

enum {
    ngx_http_zmq_default_port = 3306
};

static void       ngx_http_upstream_zmq_cleanup    (void *data);

static ngx_int_t  ngx_http_upstream_zmq_init       (ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *uscf);
static ngx_int_t  ngx_http_upstream_zmq_init_peer  (ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf);
static ngx_int_t  ngx_http_upstream_zmq_get_peer   (ngx_peer_connection_t *pc, void *data);

static void       ngx_http_upstream_zmq_free_peer  (ngx_peer_connection_t *pc, void *data, ngx_uint_t state);


/* just a work-around to override the default u->output_filter */
static ngx_int_t ngx_http_zmq_output_filter(void *data, ngx_chain_t *in);


void *
ngx_http_upstream_zmq_create_srv_conf(ngx_conf_t *cf)
{
    ngx_pool_cleanup_t                    * cln;
    ngx_http_upstream_zmq_srv_conf_t      * conf;

    zmq_debug(cf->log, "zmq create srv conf");

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_zmq_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->pool = cf->pool;

    cln = ngx_pool_cleanup_add(cf->pool, 0);

    cln->handler = ngx_http_upstream_zmq_cleanup;
    cln->data    = NULL;

    return conf;
}


/* mostly based on ngx_http_upstream_server in
 * ngx_http_upstream.c of nginx 0.8.30.
 * Copyright (C) Igor Sysoev */
char *
ngx_http_upstream_zmq_endpoint(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_zmq_srv_conf_t            * dscf = conf;
    ngx_http_upstream_zmq_endpoint_t            * ep;
    ngx_str_t                                   * value;
    ngx_uint_t                                    i;
    ngx_http_upstream_srv_conf_t                * uscf;

    zmq_debug(cf->log, "entered zmq_endpoint directive handler...");

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    if (dscf->endpoints == NULL) {
        dscf->endpoints = ngx_array_create(cf->pool, 4, sizeof(ngx_http_upstream_zmq_endpoint_t));
        if (dscf->endpoints == NULL) {
            return NGX_CONF_ERROR;
        }

        uscf->servers = dscf->endpoints;
    }

    ep = ngx_array_push(dscf->endpoints);
    if (ep == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ep, sizeof(ngx_http_upstream_zmq_endpoint_t));

    value = cf->args->elts;

    /* parse the first name:port argument */

    ep->name = value[1];

    /* parse various options */

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "rate=", sizeof("rate=") - 1)
                == 0)
        {
            int       len  = value[i].len - (sizeof("rate=") - 1);
            u_char * data  = &value[i].data[sizeof("rate=") - 1];

            ep->rate = ngx_atoi(data, len);
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\" in zmq_endpoint", &value[i]);
        return NGX_CONF_ERROR;
    }

    zmq_debug(cf->log, "reset init_upstream...");

    uscf->peer.init_upstream = ngx_http_upstream_zmq_init;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_upstream_zmq_init (ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_uint_t                               i, n;
    ngx_http_upstream_zmq_srv_conf_t       * dscf;
    ngx_http_upstream_zmq_endpoint_t         * server;
    ngx_http_upstream_zmq_peers_t          * peers;

    zmq_debug(cf->log, "zmq init");

    uscf->peer.init = ngx_http_upstream_zmq_init_peer;

    dscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_zmq_module);

    if (dscf->endpoints == NULL || dscf->endpoints->nelts == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "zmq: no zmq_endpoint defined in upstream \"%V\" in %s:%ui", &uscf->host, uscf->file_name, uscf->line);
        return NGX_ERROR;
    }

    server  = uscf->servers->elts;
    n       = uscf->servers->nelts;

    peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_zmq_peers_t) + sizeof(ngx_http_upstream_zmq_peer_t) * (n - 1));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peers->single  = (n == 1);
    peers->number  = n;
    peers->name    = &uscf->host;

    n = 0;
    for (i = 0; i < uscf->servers->nelts; i++) {
        peers->peer[n].name = server[i].name;
        peers->peer[n].rate = server[i].rate;

        n++;
    }

    dscf->peers         = peers;
    dscf->active_conns  = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_zmq_init_peer (ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_http_upstream_zmq_peer_data_t       * dp;
    ngx_http_upstream_zmq_srv_conf_t        * dscf;
    ngx_http_upstream_t                     * u;
    ngx_http_core_loc_conf_t                * clcf;
    ngx_http_zmq_loc_conf_t                 * dlcf;
    ngx_zmq_mixed_t                         * mmsg;
    ngx_str_t                                 msg;

    zmq_debug(r->connection->log, "zmq init peer");

    dp = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_zmq_peer_data_t));
    if (dp == NULL) {
        goto failed;
    }

    u = r->upstream;

    dp->upstream = u;
    dp->request  = r;
    dp->last_out = &u->out_bufs;


    dscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_zmq_module);
    dp->srv_conf = dscf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_zmq_module);
    dp->loc_conf = dlcf;

    /* to force ngx_output_chain not to use ngx_chain_writer */

    u->output.output_filter = ngx_http_zmq_output_filter;
    u->output.filter_ctx = r;
    u->output.in   = NULL;
    u->output.busy = NULL;

    u->peer.data  = dp;
    u->peer.get   = ngx_http_upstream_zmq_get_peer;
    u->peer.free  = ngx_http_upstream_zmq_free_peer;

    /* prepare the message */

    mmsg = dlcf->zmsg;
    if (mmsg->cv) {
        /* complex value */
        zmq_debug(r->connection->log, "using complex value");

        if (ngx_http_complex_value(r, mmsg->cv, &msg) != NGX_OK) {
            goto failed;
        }

        if (msg.len == 0) {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "zmq: empty \"zmq_msg\" (was: \"%V\") in location \"%V\"",
                          &mmsg->cv->value,
                          &clcf->name);

            goto failed;
        }

        {
            zmq_msg_init_size (&dp->zmsg, msg.len);
            ngx_memcpy(zmq_msg_data (&dp->zmsg), msg.data, msg.len);
        }

        return NGX_OK;
    } else {
        /* simple value */
        zmq_debug(r->connection->log, "using simple value");

        zmq_msg_init_size (&dp->zmsg, mmsg->sv.len);
        ngx_memcpy(zmq_msg_data (&dp->zmsg), mmsg->sv.data, mmsg->sv.len);


        return NGX_OK;
    }

failed:
#if defined(nginx_version) && (nginx_version >= 8017)
    return NGX_ERROR;
#else
    r->upstream->peer.data = NULL;

    return NGX_OK;
#endif
}


static ngx_int_t
ngx_http_upstream_zmq_get_peer(ngx_peer_connection_t *pc, void *data)
{
    //ngx_http_zmq_main_conf_t              * lmcf;
    ngx_http_upstream_zmq_peer_data_t       * dp = data;
    ngx_http_upstream_zmq_srv_conf_t        * dscf;
    ngx_http_upstream_zmq_peers_t           * peers;
    ngx_http_upstream_zmq_peer_t            * peer;
#if defined(nginx_version) && (nginx_version < 8017)
    ngx_http_zmq_ctx_t                      * dctx;
#endif
    ngx_connection_t                        * c        = NULL;
    void                                    * zsock    = NULL;
    int                                       fd       = (-1);
    size_t                                    fd_size  = sizeof(fd);
    ngx_event_t                             * rev;
    ngx_event_t                             * wev;
    ngx_int_t                                 rc;
    void                                    * context;

    zmq_debug(pc->log, "zmq get peer");

#if defined(nginx_version) && (nginx_version < 8017)
    if (data == NULL) {
        goto failed;
    }

    dctx = ngx_http_get_module_ctx(dp->request, ngx_http_zmq_module);
#endif

    dscf = dp->srv_conf;

    zmq_debug(pc->log, "active conns %d", (int) dscf->active_conns);


    peers       = dscf->peers;
    peer        = &peers->peer[0];              /* TODO: we only use the first endpoint  */

    dp->name    = &peer->name;

    pc->name    = &peer->name;
    pc->cached  = 0;

    /* start the zmq socket */
    context = dp->loc_conf->main_conf->zcontext;

    if (context == NULL)
    {
        zmq_debug(pc->log, "creating zmq context...");
        dp->loc_conf->main_conf->zcontext = zmq_init(1);
        if (!dp->loc_conf->main_conf->zcontext) {
            if (errno == EINVAL) {
                zmq_debug(pc->log, "zmq: invalid number of iothreads");
                return NGX_ERROR;
            } else {
                zmq_debug(pc->log, "zmq: when creating context: %d, %s", errno, zmq_strerror(errno));
                return NGX_ERROR;
            }
        }
        context = dp->loc_conf->main_conf->zcontext;
        zmq_debug(pc->log, "... 0x%p context created", context);
    }
    else
    {
        zmq_debug(pc->log, "using existing zmq context 0x%p", context);
    }

    if (dp->zsock == NULL)
    {
        zmq_debug(pc->log, "creating zmq socket in context 0x%p", context);
        dp->zsock = zmq_socket (context, ZMQ_PUB);           /* TODO: support other socket types */
        if (dp->zsock == NULL) {
            ngx_log_error(NGX_LOG_EMERG, pc->log, 0, "zmq: failed to connect: %s in upstream \"%V\"", &peer->name);

#if defined(nginx_version) && (nginx_version >= 8017)
            return NGX_DECLINED;
#else
            dctx->status = NGX_HTTP_BAD_GATEWAY;
            goto failed;
#endif
        }

        zmq_debug(pc->log, "0x%p zsocket created", dp->zsock);

        dscf->active_conns++;

        /* add the file descriptor (fd) into an nginx connection structure */
        /* get the zmq socket descriptor */

        rc = zmq_getsockopt(dp->zsock, ZMQ_FD, &fd, &fd_size);
        if (rc != 0)
        {
            ngx_log_error(NGX_LOG_ERR, pc->log, 0, "zmq: failed to get the zeromq connection fd with zmq_getsockopt");
            goto invalid;
        }

        if (fd == -1) {
            ngx_log_error(NGX_LOG_ERR, pc->log, 0, "zmq: failed to get the zeromq connection fd");
            goto invalid;
        }

        zmq_debug(pc->log, "zmq socket uses fd:%d", fd);

        c = pc->connection = ngx_get_connection(fd, pc->log);

        if (c == NULL) {
            ngx_log_error(NGX_LOG_ERR, pc->log, 0, "zmq: failed to get a free nginx connection");
            goto invalid;
        }

        c->log = pc->log;
        c->log_error = pc->log_error;
        c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

        rev = c->read;
        wev = c->write;

        rev->log = pc->log;
        wev->log = pc->log;

        /* register the connection with the zeromq fd into the nginx event model */

        if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
            zmq_debug(pc->log, "NGX_USE_RTSIG_EVENT");
            rc = ngx_add_conn(c);
        } else if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
            zmq_debug(pc->log, "NGX_USE_CLEAR_EVENT");
            rc = ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT);
            if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, pc->log, 0, "zmq: failed to add nginx connection");

                goto invalid;
            }
        } else {
            zmq_debug(pc->log, "use other event...");
            rc = ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT);
        }

        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, pc->log, 0, "zmq: failed to add connection into nginx event model");
            goto invalid;
        }

        zmq_debug(pc->log, "connecting to zmq endpoint");
        dp->state = state_zmq_disconnected;
        c->log->action = "connecting to zmq endpoint";

        if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, pc->log, 0, "zmq: failed to add connection into nginx event model");

                goto invalid;
            }
        }
    }
    else
    {
        zmq_debug(pc->log, "using existing zsock 0x%p", dp->zsock);
    }

    zmq_debug(pc->log, "returning NGX_AGAIN");
    return NGX_AGAIN;

invalid:
    zmq_debug(pc->log, "error: freeing connection");
    ngx_http_upstream_zmq_free_connection (pc->log, pc->connection, zsock, dscf);

#if defined(nginx_version) && (nginx_version >= 8017)
    return NGX_ERROR;
#else
failed:
    /* a bit hack-ish way to return error response (setup part) */
    pc->connection = ngx_get_connection(0, pc->log);
    return NGX_AGAIN;
#endif
}


static void
ngx_http_upstream_zmq_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state)
{
    ngx_http_upstream_zmq_peer_data_t   *dp = data;
    ngx_http_upstream_zmq_srv_conf_t    *dscf;

    zmq_debug(pc->log, "free peer");

#if defined(nginx_version) && (nginx_version < 8017)
    if (data == NULL) {
        return;
    }
#endif

    dscf = dp->srv_conf;

    if (pc->connection) {
        zmq_debug(pc->log, "actually free the zsocket");

        ngx_http_upstream_zmq_free_connection(pc->log, pc->connection, dp->zsock, dscf);

        dp->zsock      = NULL;
        pc->connection = NULL;
    }
}


static ngx_int_t
ngx_http_zmq_output_filter(void *data, ngx_chain_t *in)
{
    ngx_http_request_t              *r = data;
    ngx_int_t                        rc;

    zmq_debug(r->connection->log, "output filter");

    /* just to ensure u->reinit_request always gets called for upstream_next */
    r->upstream->request_sent = 1;

    rc = ngx_http_zmq_process_events(r);

    zmq_debug(r->connection->log, "process events returns %d", (int) rc);

    /* discard the ret val from process events because
     * we can only return NGX_AGAIN here to prevent
     * ngx_http_upstream_process_header from being called
     * and avoid u->write_event_handler to be set to
     * ngx_http_upstream_dummy. */

    return NGX_AGAIN;
}


ngx_flag_t
ngx_http_upstream_zmq_is_my_peer(const ngx_peer_connection_t    *peer)
{
    return (peer->get == ngx_http_upstream_zmq_get_peer);
}


void
ngx_http_upstream_zmq_free_connection(ngx_log_t *log,
        ngx_connection_t *c, void *zsock,
        ngx_http_upstream_zmq_srv_conf_t *dscf)
{
    ngx_event_t  *rev, *wev;

    zmq_debug(log, "free peer connection");

    dscf->active_conns--;

    if (zsock) {
        zmq_debug (log, "closing zsocket with zmq_close()");
        /* close and free the zsocket */
        zmq_close(zsock);
        ngx_pfree(dscf->pool, zsock);
    }

    if (c) {
        rev = c->read;
        wev = c->write;

        if (rev->timer_set) {
            ngx_del_timer(rev);
        }

        if (wev->timer_set) {
            ngx_del_timer(wev);
        }

        if (ngx_del_conn) {
            zmq_debug (log, "removing connection from nginx list");
            ngx_del_conn(c, NGX_CLOSE_EVENT);
        } else {
            if (rev->active || rev->disabled) {
                zmq_debug (log, "removing read event on socket");
                ngx_del_event(rev, NGX_READ_EVENT, NGX_CLOSE_EVENT);
            }

            if (wev->active || wev->disabled) {
                zmq_debug (log, "removing write event on socket");
                ngx_del_event(wev, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
            }
        }

        if (rev->prev) {
            ngx_delete_posted_event(rev);
        }

        if (wev->prev) {
            ngx_delete_posted_event(wev);
        }

        rev->closed = 1;
        wev->closed = 1;

        ngx_free_connection(c);
    }
}


ngx_http_upstream_srv_conf_t *
ngx_http_upstream_zmq_add(ngx_http_request_t *r, ngx_url_t *url)
{
    ngx_http_upstream_main_conf_t  *umcf;
    ngx_http_upstream_srv_conf_t  **uscfp;
    ngx_uint_t                      i;

    zmq_debug (r->connection->log, "upstream add handler");

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len != url->host.len
            || ngx_strncasecmp(uscfp[i]->host.data, url->host.data, url->host.len)
               != 0)
        {
            zmq_debug(r->connection->log, "upstream_add: host not match");
            continue;
        }

        if (uscfp[i]->port != url->port) {
            zmq_debug(r->connection->log, "upstream_add: port not match: %d != %d", (int) uscfp[i]->port, (int) url->port);
            continue;
        }

        if (uscfp[i]->default_port && url->default_port
            && uscfp[i]->default_port != url->default_port)
        {
            zmq_debug(r->connection->log, "upstream_add: default_port not match");
            continue;
        }

        return uscfp[i];
    }

    zmq_debug(r->connection->log, "No upstream found: %.*s", (int) url->host.len, url->host.data);

    return NULL;
}


static void
ngx_http_upstream_zmq_cleanup(void *data)
{
}

