/* gohttpd.h - defines for the go httpd
 * Copyright (C) 2002-2018 Sean MacLennan <seanm@seanm.ca>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this project; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */
#ifndef _GOHTTPD_H_
#define _GOHTTPD_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(__linux__) || defined(__FreeBSD__)
#define USE_SENDFILE
#endif
//#define HAVE_INET_NTOP

/* If defined we allow directory listings */
//#define ALLOW_DIR_LISTINGS

#define GOHTTPD_STR	"Apache"
#define GOHTTPD_VERSION	"0.2"

#define SERVER_STR "Server: " GOHTTPD_STR "/" GOHTTPD_VERSION " (Unix)\r\n"
#define MAX_SERVER_STRING	(sizeof(SERVER_STR) + 1)

#define HTML_INDEX_FILE	"index.html"

#define MAX_LINE	1024 /* Max seen about 600 */
#define MIN_REQUESTS	4
#define HTTP_BACKLOG	10 /* helps when backed up */

/*
 * Simplistic connection timeout mechanism.
 * Every connection has a `last access time' associated with it. An
 * access is a new connection, a read, or a write. When we have been
 * idle for POLL_TIMEOUT, we check all the connections. If a
 * connection has been idle for more than MAX_IDLE_TIME, we close the
 * connection.
 */
#define POLL_TIMEOUT	1000	/* milliseconds */
#define MAX_IDLE_TIME	60	/* seconds */

#define HTTP_ROOT	"/var/www/htdocs"
#define HTTP_CHROOT	"/var/www"
#define HTTP_PIDFILE	"/var/run/gohttpd.pid"
#define HTTP_CONFIG	"/etc/gohttpd.conf"
#define HTTP_PORT	80
#define HTTP_USER	"apache"

#define HTTP_LOGFILE	"/var/log/gohttpd/gohttpd.log"
#define HTTP_LOG_CHROOT	"/logs/gohttpd.log"

struct connection {
	int conn_n;
	struct pollfd *ufd;
#ifdef HAVE_INET_NTOP
	struct sockaddr_storage sock_addr;
#else
	struct sockaddr_in sock_addr;
#endif
	char cmd[MAX_LINE];
	off_t offset;
	unsigned int len;
	int   status;
#ifdef USE_SENDFILE
	struct iovec iovs[1];
#elif defined(ALLOW_DIR_LISTINGS)
	struct iovec iovs[3];
#else
	struct iovec iovs[2];
#endif
	int n_iovs;

#ifdef USE_SENDFILE
	int in_fd;
	off_t in_offset;
#else
	unsigned char *buf;
	unsigned int mapped;
#endif

	time_t access;

	/* http stuff */
	int http;
#define	HTTP_GET	1
#define HTTP_HEAD	2
	char *user_agent; /* combined log only */
	char *referer;    /* combined log only */
	/* The http_header needs to be big enough to store an http
	 * error reply (not counting 301 errors). The largest error
	 * packet right now is 315 with stock SERVER_STR.
	 */
	char http_header[512];
	char *errorstr; /* for large 301 replies */
	struct connection *next;
};

const char *ntoa(struct connection *conn); /* helper */

/* exported from log.c */
int  log_open(char *log_name);
void log_hit(struct connection *conn, unsigned int status);
void log_close(void);

/* exported from config.c */
extern char *config;
extern char *root_dir;
extern char *chroot_dir;
extern char *logfile;
extern char *pidfile;
extern int   port;
extern char *user;
extern uid_t uid;
extern gid_t gid;
extern int   max_conns;
extern int   do_chroot;

void read_config(char *fname);
void fatal_error(const char *msg, ...);

int do_dir(struct connection *conn, int fd, const char *dirname);

#define SOCKET(c)	((c)->ufd->fd)

#define set_writeable(c) ((c)->ufd->events = POLLOUT)

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#endif /* _GOHTTPD_H_ */

/*
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * tab-width: 8
 * End:
 */
