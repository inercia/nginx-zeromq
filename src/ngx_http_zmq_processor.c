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

#include "ngx_http_zmq_processor.h"
#include "ngx_http_zmq_module.h"
#include "ngx_http_zmq_util.h"
#include "ngx_http_upstream_zmq.h"

#include <assert.h>


static ngx_int_t ngx_http_upstream_zmq_connect(ngx_http_request_t *r,
        ngx_connection_t *c, ngx_http_upstream_zmq_peer_data_t *dp,
        void *socket);

static ngx_int_t ngx_http_upstream_zmq_send(ngx_http_request_t *r,
        ngx_connection_t *c, ngx_http_upstream_zmq_peer_data_t *dp,
        void *socket);


ngx_int_t
ngx_http_zmq_process_events (ngx_http_request_t *r)
{
    ngx_http_upstream_t                         *u;
    ngx_connection_t                            *c;
    ngx_http_upstream_zmq_peer_data_t           *dp;
    void                                        *zsocket;
    ngx_int_t                                    rc               = NGX_DONE;
    ngx_fd_t                                     fd;

    unsigned int                                 zmq_events;
    size_t                                       zmq_events_size  = sizeof(zmq_events);

    u  = r->upstream;
    c  = u->peer.connection;
    fd = c->fd;

    dp       = u->peer.data;
    zsocket  = dp->zsock;

    zmq_debug(r->connection->log, "zmq process events, fd:%d, zsock:%p, state:%d", fd, zsocket, (int)dp->state);

    if ( ! ngx_http_upstream_zmq_is_my_peer(&u->peer)) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "process events: it seems you are using a non-zmq upstream backend");
        return NGX_ERROR;
    }

    zmq_getsockopt(zsocket, ZMQ_EVENTS, &zmq_events, &zmq_events_size);
    zmq_debug(r->connection->log, "         events: %x", zmq_events);

    switch (dp->state) {
        case state_zmq_disconnected:
            rc = ngx_http_upstream_zmq_connect(r, c, dp, zsocket);
            break;

        case state_zmq_connecting:
            if (zmq_events & ZMQ_POLLOUT)
            {
                zmq_debug(r->connection->log, "changing state to connected");
                dp->state = state_zmq_connected;
                rc = NGX_AGAIN;
            }
            break;

        case state_zmq_connected:

        case state_zmq_send_pending:
            if (zmq_events & ZMQ_POLLOUT)
            {
                zmq_debug(r->connection->log, "sending msg to zeromq endpoint");
                c->log->action = "sending msg to zeromq endpoint";
                rc = ngx_http_upstream_zmq_send(r, c, dp, zsocket);
            }
            break;

        default:
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "unknown state: %d", (int) dp->state);
            return NGX_ERROR;
    }

    zmq_debug(r->connection->log, "rc == %d", (int) rc);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        zmq_debug(r->connection->log, "finalizing request");
        ngx_http_upstream_zmq_finalize_request(r, u, rc);
        return NGX_ERROR;
    }

    return rc;
}


static ngx_int_t
ngx_http_upstream_zmq_connect(ngx_http_request_t *r, ngx_connection_t *c, ngx_http_upstream_zmq_peer_data_t *dp, void *dc)
{
    ngx_http_upstream_t         * u;
    int                           zmq_rc;
    char                          ep[1024];


    u = r->upstream;

    assert(dp->name->data != NULL);
    assert(dp->name->len > 0);
    assert(dp->zsock != NULL);

    if (dp->state == state_zmq_disconnected)
    {
        ngx_memcpy(ep, dp->name->data, dp->name->len);
        ep[dp->name->len] = '\0';

        zmq_debug(r->connection->log, "starting connection to %s", ep);

        zmq_rc = zmq_connect (dp->zsock, ep);
        if (zmq_rc  != 0)
        {
           ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to connect: %d", (int) zmq_rc);
           return NGX_ERROR;
        }

        zmq_debug(r->connection->log, "changing state to connecting");
        dp->state = state_zmq_connecting;
        c->log->action = "connecting to endpoint";
    }
    else
    {
        zmq_debug(r->connection->log, "WARNING: trying to connect when state is %d", dp->state);
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_upstream_zmq_send(ngx_http_request_t *r, ngx_connection_t *c, ngx_http_upstream_zmq_peer_data_t *dp, void *dc)
{
//  ngx_http_upstream_t         *u = r->upstream;
//  int                          ret;
    ngx_int_t                    rc;
    int msg_len;

    msg_len = (int) zmq_msg_size(&dp->zmsg);
    if (msg_len > 0)
    {
        zmq_debug(r->connection->log, "sending message of size %d, zsock:%p", msg_len, dp->zsock);

        rc = zmq_send (dp->zsock, &dp->zmsg, ZMQ_NOBLOCK);
        zmq_msg_close (&dp->zmsg);
        if (rc != 0)
        {
            return NGX_ERROR;
        }
    }
    else
    {
        zmq_debug(r->connection->log, "nothing to send, zsock:%p", dp->zsock);
    }

    return NGX_HTTP_CLOSE;   /* close the connection with no response */
}



void
ngx_http_upstream_zmq_done(ngx_http_request_t *r,
        ngx_http_upstream_t *u, ngx_http_upstream_zmq_peer_data_t *dp,
        ngx_int_t rc)
{
    ngx_connection_t            *c;

    zmq_debug(r->connection->log, "enter");

    //(void) ngx_http_zmq_output_bufs(r, dp);

    zmq_debug(r->connection->log, "after output bufs");

    /* to persuade Maxim Dounin's ngx_http_upstream_keepalive module to cache the current connection */

    u->length = 0;

    if (rc == NGX_DONE) {
        u->header_sent = 1;
        u->headers_in.status_n = NGX_HTTP_OK;
        rc = NGX_OK;
    } else {
        r->headers_out.status = rc;
        u->headers_in.status_n = rc;
    }

    c = u->peer.connection;

    /* reset the state machine */
    c->log->action = "being idle";
    dp->state = state_zmq_connected;

    zmq_debug(r->connection->log, "about to finalize request...");
    ngx_http_upstream_zmq_finalize_request(r, u, rc);
    zmq_debug(r->connection->log, "after finalize request...");
}

