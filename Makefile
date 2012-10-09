#
# simple Makefile
#
# DO NOT USE THIS MAKEFILE unless you are a developer
# just go to the nginx source dir and build with something like:
#  ./configure ... --add-module=THIS_DIR && make
#

CC              = /usr/local/bin/ccache-gcc
CWD             = $(shell pwd)
NGINX_DIR       = ../nginx-0.8.54
NGINX_CONF_ARGS = \
    --without-mail_pop3_module  \
	--without-mail_imap_module  \
	--without-mail_smtp_module  \
	--with-file-aio  \
	--with-debug
	




all: $(NGINX_DIR)/Makefile
	make -C $(NGINX_DIR)  build


$(NGINX_DIR)/Makefile:  $(NGINX_DIR)/configure
	cd $(NGINX_DIR) && CC=$(CC) ./configure $(NGINX_CONF_ARGS)  --add-module=$(CWD) || rm -f $(NGINX_DIR)/Makefile


clean:
	make -C $(NGINX_DIR)  clean
	rm -f $(NGINX_DIR)/Makefile

