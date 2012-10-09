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

#ifndef DDEBUG_H
#define DDEBUG_H

#include <ngx_core.h>

#if defined(DDEBUG) && (DDEBUG)
#   define dd_dump_chain_size() { \
        int              n; \
        ngx_chain_t     *cl; \
            \
        for (n = 0, cl = u->out_bufs; cl; cl = cl->next, n++) { \
        } \
            \
        zmq_debug("chain size: %d", n); \
    }
#   if (NGX_HAVE_VARIADIC_MACROS)

#       define zmq_debug(L, ...)   { \
                           char logline[1024]; \
                           sprintf(logline, __VA_ARGS__); \
                           ngx_log_error_core (NGX_LOG_DEBUG, L, 0, "zmq [%s:%d]: %s", __func__, __LINE__, logline); \
                         }

#   else

#include <stdarg.h>
#include <stdio.h>
#include <stdarg.h>

static void zmq_debug(const char * fmt, ...) {
}

#    endif

#else

#   define dd_dump_chain_size()
#   if (NGX_HAVE_VARIADIC_MACROS)
#       define zmq_debug(...)
#   else

#include <stdarg.h>

static void zmq_debug(const char * fmt, ...) {
}

#   endif

#endif

#if defined(DDEBUG) && (DDEBUG)

#define dd_check_read_event_handler(r)   \
    zmq_debug("r->read_event_handler = %s", \
        r->read_event_handler == ngx_http_block_reading ? \
            "ngx_http_block_reading" : \
        r->read_event_handler == ngx_http_test_reading ? \
            "ngx_http_test_reading" : \
        r->read_event_handler == ngx_http_request_empty_handler ? \
            "ngx_http_request_empty_handler" : "UNKNOWN")

#define dd_check_write_event_handler(r)   \
    zmq_debug("r->write_event_handler = %s", \
        r->write_event_handler == ngx_http_handler ? \
            "ngx_http_handler" : \
        r->write_event_handler == ngx_http_core_run_phases ? \
            "ngx_http_core_run_phases" : \
        r->write_event_handler == ngx_http_request_empty_handler ? \
            "ngx_http_request_empty_handler" : "UNKNOWN")

#else

#define dd_check_read_event_handler(r)
#define dd_check_write_event_handler(r)

#endif


#endif



