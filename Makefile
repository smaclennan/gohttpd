.PHONY: all install clean

CC = cc
#CC = clang -fno-color-diagnostics

# If you set D=1 on the command line then $(D:1=-g)
# returns -g, else it returns the default (-O2).
D = -O2
CFLAGS += -Wall $(D:1=-g)

ETAGS=`which etags || echo true`

CFILES = gohttpd.c config.c log.c

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

all:	gohttpd gostats

gohttpd: $O
	$(QUIET_LINK)$(CC) -o $@ $O $(LIBS)
	@$(ETAGS) $(CFILES) *.h

gostats: gostats.c
	$(QUIET_LINK)$(CC) -o $@ $<

# Make all c files depend on all .h files
*.o: *.h

# SAM not done
install: all

clean:
	$(RM) *.o gohttpd gostats TAGS
