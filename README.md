Name
====
    ngx_zeromq - an upstream module that talks to
        mysql, zeromq, and sqlite3 by libzeromq

Status
======
    This module is in development!

Synopsis
========

    http {
        ...

        upstream cluster {
            # simple round-robin
            zeromq_server 127.0.0.1:3306 dbname=test
                 password=some_pass user=monty protocol=mysql;
            zeromq_server 127.0.0.1:1234 dbname=test2
                 password=pass user=bob protocol=zeromq;
        }

        upstream backend {
            zeromq_server 127.0.0.1:3306 dbname=test
                 password=some_pass user=monty protocol=mysql;
        }

        server {
            location /api {
                zeromq_pass backend;

                zeromq_connect_timeout 500 ms; # default 60 s
            }
            ...
        }
    }

Description
===========

    This is an nginx upstream module integrating libzeromq
    into nginx in an non-blocking and streamming way.

    Essentially it provides a very efficient and flexible way
    for nginx internals to access zeromq.

    It also has a builtin per-worker connection pool
    mechanism.

    Here's a sample configuration:

        upstream backend {
            zeromq_server 127.0.0.1:3306;
            zeromq_keepalive max=100 mode=single overflow=reject;
        }

    The zeromq_keepalive directive has the following options:

        * max=<num>
            Specify the capacity of the connection pool for
            the current upstream block. The <num> value MUST
            be non-zero. If set to 0, it effectively disables
            the connection pool. And this is the default
            if no "zeromq_keepalive" directive is specified.

        * mode=<mode>
            This supports two values, "single" and "multi".
            "single" mode means the pool does not distinguish
            various zeromq servers in the current ustream
            block while "multi" means the pool will merely
            reuse connections which have identical server
            host names and ports. Note that it will igore
            differences between dbnames or users.
            Default to "single".

        * overflow=<action>
            This option specifies what to do when the
            connection pool is already full while new
            database connection is required. Either "reject"
            (without quotes) or "ignore" can be specified.
            In case of "reject", it will reject the current
            request, and returns "503 Service Unavaliable"
            error page. For "ignore", this module will
            go on creating a new DB connection.

    For now, the connection pool uses a simple LIFO algorithm
    to assign idle connections in the pool. That is,
    most recently (successfully) used connections will be
    reused first the next time. And new idle connections
    will always replace the oldest idle connections in the
    pool even if the pool is already full.

Caveats
=======

    * Other usptream modules like "upstream_hash" and
      "upstream_keepalive" MUST NOT be used with this module
      in a single upstream block.

    * Directives like "server" MUST NOT be mixed with
      "zeromq_server" either.

    * Upstream backends that don't use "zeromq_server" to
      define server entries MUST NOT be used in the
      "zeromq_pass" directive.

Directives
==========

    zeromq_server <host>:<port>.

    zeromq_connect_timeout <time>
        <time> can be an integer, with an optional time unit, like "s", "ms", "m".
        The default time unit is "s", ie, "second".

        default setting is "60 s".

    zeromq_buffer_size <size>
        the buffer size for zeromq outputs. default to the page size (4k/8k).
        the larger the buffer, the less streammy the outputing process will be.

Output (TODO)
=============

    This module generates binary query results in a format
    that will be shared among the various nginx database
    driver modules like ngx_postgresql and ngx_oracle.
    This data format is named "Resty DBD Stream" (RDS).

    If you're a web app developer, you may be more interested
    in using a source filter module like ngx_rds_json module
    ( http://github.com/agentzh/rds-json-nginx-module ) to
    obtain JSON output.

    For the HTTP response header part, the 200 OK status
    code should always be returned.

    The Content-Type header MUST be set to
    "application/x-resty-dbd-stream" (without quotes).

    And the driver generating this response is also set a
    X-Resty-DBD header. For instance, this
    module adds the following output header:

        X-Resty-DBD-Module: zeromq 0.0.1

    where 0.0.1 is this module's own version number. This
    X-Resty-DBD-Module header is optional though.

    Below is the HTTP response body format (version 0.0.3):

    Header part
        uint8_t        endian type (1 means big-endian and little
                       endian otherwise)

        uint32_t       format version
                       (v1.2.3 is represented as 1002003 in
                        decimal)

        uint8_t        result type
                       (0 means normal SQL result type,
                        fixed for now)

        uint16_t       standard error code
        uint16_t       driver-specific error code

        uint16_t       driver-specific error string length
        u_char*        driver-specific error string data

        uint64_t       database rows affected
        uint64_t       insert id (if none, 0)
        uint16_t       column count

    Body part

      when the "column count" field in the Header part
      is zero, then the whole body part is omitted.

      0*Column (number of columns is determined by "column count")

        uint16_t        non-zero value for standard column type
                        code and for the column list
                        terminatoandr otherwise.
        uint16_t        driver-specific column type code
        uint16_t        column name length
        u_char*         column name data

      0*Row (terminated by 8-bit zero)

        uint8_t         valid row (1 means valid, and 0 means
                        the row list terminator)

        0*Field (count is predetermined by column number)
            uint32_t        field length ((uint32_t) -1 represents NULL)
            uint8_t*        field data (in textual representation), is empty
                            if field length == (uint32_t) -1

    On the nginx output chain link level, the following
    components should be put into a single ngx_buf_t struct:

        * the header

        * each column and the column list terminator

        * each row's valid flag byte and row list terminator

        * each field in each row (if any) but the field data
          can span multiple bufs
