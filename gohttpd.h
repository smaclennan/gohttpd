/*
 * gohttpd.h - defines for the go httpd
 * Copyright (C) 2015 Sean MacLennan <seanm@seanm.ca>
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
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <sys/uio.h>
#include <sys/poll.h>

#define GOHTTPD_VERSION "0.1"

#define MAX_HOSTNAME	65
#define MAX_LINE	2048 /* Older versions of Lynx send a huge line */
#define MIN_REQUESTS	4
#define HTTP_BACKLOG	10 /* helps when backed up */

/*
 * Simplistic connection timeout mechanism.
 * Every connection has a `last access time' associated with it. An
 * access is a new connection, a read, or a write. When we have been
 * idle for POLL_TIMEOUT seconds, we check all the connections. If a
 * connection has been idle for more than MAX_IDLE_TIME, we close the
 * connection.
 */
#define POLL_TIMEOUT	 1	/* seconds */
#define MAX_IDLE_TIME	60	/* seconds */

#define HTTP_ROOT		"/var/www"
#define HTTP_LOGFILE	"/var/log/gohttpd.log"
#define HTTP_PIDFILE	"/var/run/gohttpd.pid"
#define HTTP_CONFIG		"/etc/gohttpd.conf"
#define HTTP_PORT	80

/* Set to 1 to not log the local network (192.168.x.x).
 * Set to 0 to log everything. Do not undefine.
 */
#define IGNORE_LOCAL	1

#define HTTP_USER		"httpd"
#define HTTP_UID		-1
#define HTTP_GID		-1

struct connection {
	int conn_n;
	struct pollfd *ufd;
	void *sock_addr;
	char *cmd;
	off_t offset;
	unsigned len;
	unsigned char *buf;
	unsigned mapped;
	int   status;
	struct iovec iovs[4];
	int n_iovs;

	time_t access;

	/* http stuff */
	int http;
#define	HTTP_GET	1
#define HTTP_HEAD	2
	char *user_agent; /* combined log only */
	char *referer;    /* combined log only */
	char *http_header;
};

/* exported from gohttpd.c */
extern int verbose;

void close_connection(struct connection *conn, int status);
int checkpath(char *path);

/* exported from log.c */
int  log_open(char *log_name);
void log_hit(struct connection *conn, unsigned status);
void log_close(void);
void send_error(struct connection *conn, unsigned error);

/* exported from socket.c */
int listen_socket(int port);
int accept_socket(int sock, struct connection *conn);
const char *ntoa(struct connection *conn); /* helper */
void alloc_sock_addr(struct connection *conn);


/* exported from config.c */
extern char *config;
extern char *root_dir;
extern char *logfile;
extern char *pidfile;
extern char *hostname;
extern int   port;
extern char *user;
extern uid_t uid;
extern gid_t gid;
extern int   max_conns;
extern int   do_chroot;

int read_config(char *fname);

/* exported from http.c */
int http_init(void);
void http_cleanup(void);
int http_get(struct connection *conn);
int http_send_response(struct connection *conn);
int http_error(struct connection *conn, int status);

extern unsigned bad_munmaps;
void mmap_release(struct connection *conn);
int READ(int handle, char *whereto, int len);
int WRITE(int handle, char *whereto, int len);

#define SOCKET(c)	((c)->ufd->fd)

#define set_readable(c, sock)				\
	do {						\
		(c)->ufd->fd = sock;			\
		(c)->ufd->events = POLLIN;		\
		if ((c)->conn_n + 2 > npoll)		\
			npoll = (c)->conn_n + 2;	\
	} while (0)

#define set_writeable(c)			\
	do {					\
		(c)->ufd->events = POLLOUT;	\
	} while (0)

#endif /* _GOHTTPD_H_ */
