.PHONY: all install clean

CC = cc
#CC = clang -fno-color-diagnostics

# If you set D=1 on the command line then $(D:1=-g)
# returns -g, else it returns the default (-O2).
D = -g # SAM debug to -g during development -O2
CFLAGS += -Wall $(D:1=-g)

ETAGS=`which etags || echo true`

CFILES = gohttpd.c config.c log.c socket.c

O := $(CFILES:.c=.o)

#################

#
# Pretty print - "borrowed" from sparse Makefile
#
V	      = @
Q	      = $(V:1=)
QUIET_CC      = $(Q:@=@echo    '     CC       '$@;)
QUIET_LINK    = $(Q:@=@echo    '     LINK     '$@;)

.c.o:
	$(QUIET_CC)$(CC) -o $@ -c $(CFLAGS) $<

#################

all:	gohttpd

gohttpd: $O
	$(QUIET_LINK)$(CC) -o $@ $O $(LIBS)
	@$(ETAGS) $(CFILES) *.h

# Make all c files depend on all .h files
*.o: *.h

# SAM not done
install: all

clean:
	rm -f *.o gohttpd TAGS
