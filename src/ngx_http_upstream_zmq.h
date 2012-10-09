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

#ifndef NGX_HTTP_UPSTREAM_ZMQ_H
#define NGX_HTTP_UPSTREAM_ZMQ_H

#include "ngx_http_zmq_module.h"

#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include <zmq.h>




typedef struct {
    ngx_str_t                        name;       /* something like "tcp://127.0.0.1:5000"  */
    ngx_uint_t                       rate;

}
ngx_http_upstream_zmq_endpoint_t;


typedef struct {
    ngx_str_t                       name;
    ngx_uint_t                      rate;
}
ngx_http_upstream_zmq_peer_t;


typedef struct {
    ngx_uint_t                           single;
    ngx_uint_t                           number;
    ngx_str_t                          * name;

    ngx_http_upstream_zmq_peer_t         peer[1];

}
ngx_http_upstream_zmq_peers_t;


typedef struct {
    ngx_http_upstream_zmq_peers_t       * peers;

    /* of ngx_http_upstream_zmq_endpoint_t */
    ngx_array_t                         * endpoints;

    ngx_pool_t                          * pool;

    ngx_uint_t                            active_conns;

} ngx_http_upstream_zmq_srv_conf_t;


typedef struct {
    ngx_http_zmq_loc_conf_t                * loc_conf;
    ngx_http_upstream_zmq_srv_conf_t       * srv_conf;

    ngx_http_upstream_t                    * upstream;
    ngx_http_request_t                     * request;

    ngx_http_zmq_state_t                     state;

    ngx_str_t                                zendpoint;
    void                                   * zsock;
    zmq_msg_t                                zmsg;

    ngx_str_t                              * name;

    ngx_chain_t                           ** last_out;

}
ngx_http_upstream_zmq_peer_data_t;




char *      ngx_http_upstream_zmq_endpoint (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

void *      ngx_http_upstream_zmq_create_srv_conf (ngx_conf_t *cf);

ngx_flag_t  ngx_http_upstream_zmq_is_my_peer (const ngx_peer_connection_t *peer);

void        ngx_http_upstream_zmq_free_connection (ngx_log_t *log, ngx_connection_t *c, void *sock, ngx_http_upstream_zmq_srv_conf_t *dscf);

ngx_http_upstream_srv_conf_t * ngx_http_upstream_zmq_add (ngx_http_request_t *r, ngx_url_t *url);


#endif


