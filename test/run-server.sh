#!/bin/sh


NGINX_DIR=../../nginx-0.8.54
NGINX_EXE=$NGINX_DIR/objs/nginx

###############################################################################

ulimit -n  5000
 
 
echo "Starting server at port 7888"
$NGINX_EXE -c $(pwd)/run-server.conf


