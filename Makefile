.PHONY: all install clean

#CC = clang -fno-color-diagnostics

# If you set D=1 on the command line then $(D:1=-g)
# returns -g, else it returns the default (-O2).
D = -O2
CFLAGS += -Wall $(D:1=-g)

ETAGS=`which etags || echo true`

# Pretty print - "borrowed" from sparse Makefile
V	      = @
Q	      = $(V:1=)
QUIET_LINK    = $(Q:@=@echo    '     LINK     '$@;)

all:	gohttpd gostats

gohttpd: gohttpd.c gohttpd.h
	$(QUIET_LINK)$(CC) -o $@ $< $(LIBS)
	@$(ETAGS) gohttpd.c gohttpd.h

gostats: gostats.c
	$(QUIET_LINK)$(CC) -o $@ $<

install: all
	install -D -m644 logrotate.gohttpd ${DESTDIR}/etc/logrotate.d/gohttpd
	install -D rc.gohttpd ${DESTDIR}/etc/rc.d/rc.gohttpd
	install -D -s gohttpd ${DESTDIR}/usr/sbin/gohttpd
	install -D -s gostats ${DESTDIR}/usr/bin/gostats

clean:
	rm -f *.o gohttpd gostats TAGS
