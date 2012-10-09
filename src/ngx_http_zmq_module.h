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

#ifndef NGX_HTTP_ZMQ_MODULE_H
#define NGX_HTTP_ZMQ_MODULE_H

#include <ngx_config.h>
#include <nginx.h>
#include <ngx_http.h>



#define ngx_http_zmq_module_version           1
#define ngx_http_zmq_module_version_string    "0.0.1"



extern ngx_module_t                       ngx_http_zmq_module;


typedef struct {
    void                                * zcontext;
}
ngx_http_zmq_main_conf_t;


typedef struct {
    ngx_uint_t                            key;
    ngx_str_t                             sv;
    ngx_http_complex_value_t            * cv;
}
ngx_zmq_mixed_t;

typedef struct {
    ngx_http_zmq_main_conf_t            * main_conf;

    ngx_http_upstream_conf_t              upstream;

    /* zmq properties */
    ngx_zmq_mixed_t                     * zmsg;
    ngx_array_t                         * zmsgs;

    ngx_http_complex_value_t            * complex_target;

    size_t                                buf_size;

}
ngx_http_zmq_loc_conf_t;



#if defined(nginx_version) && (nginx_version < 8017)
typedef struct {
    ngx_int_t                           status;
} ngx_http_zmq_ctx_t;
#endif


/* states for the zmq state machine */
typedef enum {
    state_zmq_disconnected,
    state_zmq_connecting,
    state_zmq_send_pending,
    state_zmq_connected
}
ngx_http_zmq_state_t;

#endif

