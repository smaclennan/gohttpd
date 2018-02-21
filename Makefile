.PHONY: all install clean

#CC = clang -fno-color-diagnostics

# If you set D=1 on the command line then $(D:1=-g)
# returns -g, else it returns the default (-O2).
D = -O2
CFLAGS += -Wall $(D:1=-g)

ETAGS=`which etags || echo true`

all:	gohttpd

gohttpd: gohttpd.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)
	@$(ETAGS) gohttpd.c

install: all
	install -D -m644 logrotate.gohttpd ${DESTDIR}/etc/logrotate.d/gohttpd
	install -D rc.gohttpd ${DESTDIR}/etc/rc.d/rc.gohttpd
	install -D -s gohttpd ${DESTDIR}/usr/sbin/gohttpd

clean:
	rm -f gohttpd gostats TAGS valgrind.out
