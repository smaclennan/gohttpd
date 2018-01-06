/* gohttpd.c - the mainline for the go httpd
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
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <assert.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "gohttpd.h"

static int verbose;

/* Stats */
static unsigned int max_requests;
static unsigned int max_length;
static unsigned int n_requests;
static int      n_connections; /* yes signed, I want to know if it goes -ve */
static time_t   started;

static struct connection *conns;

static struct pollfd *ufds;
static int npoll;

#if defined(USE_SENDFILE) && defined(ALLOW_DIR_LISTINGS)
#error Directory listings and sendfile are currently incompatible
#endif

/* SIGUSR1 is handled in log.c */
static void sighandler(int signum)
{
	switch (signum) {
	case SIGHUP:
	case SIGTERM:
	case SIGINT:
		/* Somebody wants us to quit */
		syslog(LOG_INFO, "gohttpd stopping.");
		log_close();
		exit(0);
	case SIGPIPE:
		/* We get a SIGPIPE if the client closes the
		 * connection on us.
		 */
		break;
	default:
		syslog(LOG_WARNING, "Got an unexpected %d signal\n", signum);
		break;
	}
}

#ifdef USE_SENDFILE
static void set_cork(int sock, int on)
{	/* Optimization - not an error if it fails */
#if defined(TCP_NOPUSH) && !defined(TCP_CORK)
#define TCP_CORK TCP_NOPUSH
#endif
	setsockopt(sock, IPPROTO_TCP, TCP_CORK, &on, sizeof(on));
}
#else
static unsigned char *mmap_get(struct connection *conn, int fd)
{
	unsigned char *mapped;

	/* We mess around with conn->len */
	conn->mapped = conn->len;
	mapped = mmap(NULL, conn->mapped, PROT_READ, MAP_SHARED, fd, 0);
	if (mapped == MAP_FAILED)
		return NULL;

#ifdef MADV_SEQUENTIAL
	/* folkert@vanheusden.com */
	(void)madvise(mapped, conn->mapped, MADV_SEQUENTIAL);
#endif

	return mapped;
}

static void mmap_release(struct connection *conn)
{
	if (munmap(conn->buf, conn->mapped))
		syslog(LOG_ERR, "munmap %p %d", conn->buf, conn->mapped);
}
#endif

/* network byte order */
const char *ntoa(struct connection *conn)
{
#ifdef HAVE_INET_NTOP
	static char a[64];
	struct sockaddr_storage *sin = &conn->sock_addr;

	return inet_ntop(sin->ss_family, sin, a, sizeof(a));
#else
	struct sockaddr_in *sin = (struct sockaddr_in *)conn->sock_addr;

	return inet_ntoa(sin->sin_addr);
#endif
}

static void close_connection(struct connection *conn, int status)
{
	char *p;

	if (verbose > 2)
		printf("Close request\n");

	--n_connections;

	/* Make sure we have a clean cmd */
	for (p = conn->cmd; *p && *p != '\r' && *p != '\n'; ++p)
		;
	*p = '\0';

	if (strncmp(conn->cmd, "GET ", 4) == 0 ||
	    strncmp(conn->cmd, "HEAD ", 5) == 0)
		conn->http = 1;

	/* Log hits in one place. Do not log stat requests. */
	if (status != 1000)
		log_hit(conn, status);

#ifdef USE_SENDFILE
	if (conn->in_fd >= 0) {
		close(conn->in_fd);
		conn->in_fd = -1;
		conn->in_offset = 0;
	}
#else
	if (conn->buf) {
		if (conn->mapped) {
			mmap_release(conn);
			conn->mapped = 0;
		} else
			free(conn->buf);
		conn->buf = NULL;
	}
#endif

	conn->len = conn->offset = 0;

	if (SOCKET(conn) >= 0) {
		close(SOCKET(conn));
		conn->ufd->fd = -1;
		conn->ufd->revents = 0;
		while (npoll > 1 && ufds[npoll - 1].fd == -1)
			--npoll;
	}

	conn->http = 0;
	conn->referer = NULL;
	conn->user_agent = NULL;
	*conn->cmd = 0;
	if (conn->errorstr) {
		free(conn->errorstr);
		conn->errorstr = NULL;
	}

	conn->status = 200;

	memset(conn->iovs, 0, sizeof(conn->iovs));

	ufds[0].events = POLLIN; /* in case we throttled */
}

static void cleanup(void)
{
	struct connection *conn;
	int i;

	close(ufds[0].fd); /* accept socket */

	/*
	 * This is mainly for valgrind.
	 * Close any outstanding connections.
	 * Free any cached memory.
	 */
	for (conn = conns, i = 0; i < max_conns; ++i, ++conn)
		if (SOCKET(conn) != -1)
			close_connection(conn, 500);

	free(user);
	free(root_dir);
	free(chroot_dir);
	free(logfile);
	free(pidfile);

	free(conns);
	free(ufds);

	closelog();
}

static int accept_socket(int sock, struct connection *conn)
{
	int new, flags;
#ifdef HAVE_INET_NTOP
	unsigned int addrlen = sizeof(struct sockaddr_storage);
#else
	unsigned int addrlen = sizeof(struct sockaddr_in);
#endif
	new = accept(sock, (void *)&conn->sock_addr, &addrlen);
	if (new < 0)
		return -1;

	flags = fcntl(new, F_GETFL, 0);
	if (flags == -1 || fcntl(new, F_SETFL, flags | O_NONBLOCK) == -1) {
		printf("fcntl failed\n");
		close(new);
		return -1;
	}

	flags = 1;
	if (setsockopt(new, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags)))
		perror("setsockopt(TCP_NODELAY)"); /* not fatal */

	return new;
}

static int new_connection(int csock)
{
	int sock;
	int i;
	struct connection *conn;

	while (1) {
		/*
		 * Find a free connection. If we do not have a free
		 * connection, throttle incoming requests and let the backlog
		 * queue hold it.
		 */
		for (conn = conns, i = 0; i < max_conns; ++i, ++conn)
			if (SOCKET(conn) == -1)
				break;
		if (i == max_conns) {
			syslog(LOG_WARNING, "Too many connections.");
			ufds[0].events = 0;
			return -1;
		}

		sock = accept_socket(csock, conn);
		if (sock < 0) {
			seteuid(uid);

			if (errno == EWOULDBLOCK)
				return 0;

			syslog(LOG_WARNING, "Accept connection: %m");
			return -1;
		}

		/* Set *before* any closes */
		set_readable(conn, sock);
		++n_connections;
		++n_requests;
		if (i > max_requests)
			max_requests = i;

		conn->offset = 0;
		conn->len    = 0;
#ifndef USE_SENDFILE
		conn->mapped = 0;
#endif
		time(&conn->access);
	}
}

#define SECONDS_IN_AN_HOUR	(60 * 60)
#define SECONDS_IN_A_DAY	(SECONDS_IN_AN_HOUR * 24)

static char *uptime(char *str, int len)
{
	time_t up = time(NULL) - started;
	int days = up / SECONDS_IN_A_DAY;
	int hours = (up % SECONDS_IN_A_DAY) / SECONDS_IN_AN_HOUR;

	snprintf(str, len, "%d day%s %d hour%s",
		 days, days == 1 ? "" : "s", hours, hours == 1 ? "" : "s");
	return str;
}

static int gohttpd_stats(struct connection *conn)
{
	char buf[128], up[20];

	snprintf(buf, sizeof(buf),
		 "gohttpd " GOHTTPD_VERSION "  %s\r\n"
		 "Requests:     %10u\r\n"
		 "Max parallel: %10u\r\n"
		 "Max length:   %10u\r\n",
		 uptime(up, sizeof(up)),
		 n_requests, max_requests, max_length);

	while (write(SOCKET(conn), buf, strlen(buf)) < 0 && errno == EINTR)
		;

	close_connection(conn, 1000);

	return 0;
}

static void check_old_connections(void)
{
	struct connection *c;
	int i;
	time_t checkpoint;

	checkpoint = time(NULL) - MAX_IDLE_TIME;

	/* Do not close the listen socket */
	for (c = conns, i = 0; i < max_conns; ++i, ++c)
		if (SOCKET(c) >= 0 && c->access < checkpoint) {
			syslog(LOG_WARNING,
			       "%s: Killing idle connection.", ntoa(c));
			close_connection(c, 408);
		}
}

static void create_pidfile(char *fname)
{
	FILE *fp;
	int n;
	int pid;

	fp = fopen(fname, "r");
	if (fp) {
		n = fscanf(fp, "%d\n", &pid);
		fclose(fp);

		if (n == 1) {
			if (kill(pid, 0) == 0)
				fatal_error("gohttpd already running (pid %d)",
					    pid);
		} else
			fatal_error("Unable to read %s", fname);
	} else if (errno != ENOENT)
		fatal_error("Open %s: %m", fname);

	fp = fopen(fname, "w");
	if (fp) {
		pid = getpid();
		fprintf(fp, "%d\n", pid);
		fclose(fp);
	} else  if (errno != EACCES)
		fatal_error("Create %s: %m", fname);
}

static void unquote(char *str)
{
	char *p, quote[3], *e;
	int n;

	for (p = str; (p = strchr(p, '%')); ) {
		quote[0] = *(p + 1);
		quote[1] = *(p + 2);
		quote[2] = '\0';
		n = strtol(quote, &e, 16);
		if (e == (quote + 2)) {
			*p++ = (char)n;
			memmove(p, p + 2, strlen(p + 2) + 1);
		} else
			++p; /* skip over % */
	}
}


static const char *msg_400 =
	"Your browser sent a request that this server could not understand.";

static const char *msg_404 =
	"The requested URL was not found on this server.";

static const char *msg_414 =
	"The requested URL was too large.";

static const char *msg_500 =
	"An internal server error occurred. Try again later.";


/* This is a very specialized build_response just for 301 errors. */
static int http_error301(struct connection *conn, char *request)
{
	char str[MAX_LINE + MAX_LINE + MAX_SERVER_STRING + 256];
	const char *title = "301 Moved Permanently";
	int n;

	n = snprintf(str, sizeof(str),
		     /* http header */
		     "HTTP/1.0 %s\r\n"
		     SERVER_STR
		     "Content-Type: text/html\r\n"
		     "Location: /%s/\r\n\r\n"
		     /* html body */
		     "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
		     "<html lang=\"en\">\n<head>\n"
		     "<title>%s</title>\r\n"
		     "</head>\n<body><h1>%s</h1>\r\n"
		     "<p>The document has moved <a href=\"/%s/\">here</a>.\r\n"
		     "</body></html>\r\n",
		     title, request, title, title, request);

	if (n < sizeof(conn->http_header)) {
		/* normal case - we fit in header */
		strcpy(conn->http_header, str);
		conn->iovs[0].iov_base = conn->http_header;
	} else {
		conn->errorstr = strdup(str);
		if (conn->errorstr == NULL) {
			syslog(LOG_WARNING, "http_error: Out of memory.");
			close_connection(conn, 301);
			return 1;
		}
		conn->iovs[0].iov_base = conn->errorstr;
	}

	conn->iovs[0].iov_len  = n;
	conn->n_iovs = 1;
	conn->status = 301;

	set_writeable(conn);

	return 0;
}

/* For all but 301 errors */
static int http_error(struct connection *conn, int status)
{
	const char *title, *msg;
	int n1;

	switch (status) {
	case 400:
		title = "400 Bad Request";
		msg = msg_400;
		break;
	case 403:
		title = "403 Forbidden";
		msg = msg_404;
		break;
	case 404:
		title = "404 Not Found";
		msg = msg_404;
		break;
	case 414:
		title = "414 Request URL Too Large";
		msg = msg_414;
		break;
	case 500:
		title = "500 Server Error";
		msg = msg_500;
		break;
	default:
		syslog(LOG_ERR, "Unknow error status %d", status);
		title = "500 Unknown";
		msg = msg_500;
		break;
	}

	n1 = snprintf(conn->http_header, sizeof(conn->http_header),
		      /* http header */
		      "HTTP/1.0 %s\r\n"
		      SERVER_STR
		      "Content-Type: text/html\r\n\r\n"
		      /* html error body */
		      "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
		      "<html lang=\"en\">\n<head>\n"
		      "<title>%s</title>\r\n"
		      "</head>\n<body><h1>%s</h1>\r\n"
		      "<p>%s\r\n"
		      "</body></html>\r\n",
		      title, title, title, msg);

	conn->status = status;

	conn->iovs[0].iov_base = conn->http_header;
	conn->iovs[0].iov_len  = n1;
	conn->n_iovs = 1;

	set_writeable(conn);

	return 0;
}

static int http_build_response(struct connection *conn)
{
	conn->status = 200;
	return snprintf(conn->http_header, sizeof(conn->http_header),
			"HTTP/1.1 200 OK\r\n"
			SERVER_STR
			"Connection: close\r\n"
			"Content-Length: %d\r\n\r\n", conn->len);
}

static int do_file(struct connection *conn, int fd)
{
	conn->len = lseek(fd, 0, SEEK_END); /* build_response needs this set */

	conn->iovs[0].iov_base = conn->http_header;
	conn->iovs[0].iov_len  = http_build_response(conn);

	if (conn->http == HTTP_HEAD) {
		/* no body to send */
		close(fd);

		conn->len = 0;
		conn->n_iovs = 1;

		return 0;
	}

#ifdef USE_SENDFILE
	conn->n_iovs = 1;
	conn->in_fd = fd;
	conn->in_offset = 0;
	set_cork(SOCKET(conn), 1);
#else
	conn->buf = mmap_get(conn, fd);

	close(fd); /* done with this */

	/* Zero length files will fail */
	if (conn->buf == NULL && conn->len) {
		syslog(LOG_ERR, "mmap: %m");
		return http_error(conn, 500);
	}

	if (conn->buf) {
		conn->iovs[1].iov_base = conn->buf;
		conn->iovs[1].iov_len  = conn->len;
	}

	conn->len = conn->iovs[0].iov_len + conn->iovs[1].iov_len;
	conn->n_iovs = 2;
#endif

	return 0;
}

static int isdir(char *name)
{
	struct stat sbuf;

	if (stat(name, &sbuf) == -1)
		return 0;
	return S_ISDIR(sbuf.st_mode);
}

int http_get(struct connection *conn)
{
	char *e;
	int fd, rc;
	char *request = conn->cmd;
	char dirname[MAX_LINE + 20];

	conn->http = *request == 'H' ? HTTP_HEAD : HTTP_GET;

	/* This works for both GET and HEAD */
	request += 4;
	while (isspace((int)*request))
		++request;

	e = strstr(request, "HTTP/");
	if (e == NULL)
		/* probably a local lynx request */
		return http_error(conn, 400);

	while (*(e - 1) == ' ')
		--e;
	*e++ = '\0';

	if (*request == '/')
		++request;

	unquote(request);

	/* Save these up front for logging */
	conn->referer = strstr(e, "Referer:");
	conn->user_agent = strstr(e, "User-Agent:");

	if (*request) {
		snprintf(dirname, sizeof(dirname) - 20, "%s", request);
		if (isdir(dirname)) {
			char *p = dirname + strlen(dirname);
			if (*(p - 1) != '/') {
				/* We must send back a 301
				 * response or relative
				 * URLs will not work
				 */
				return http_error301(conn, request);
			}
			strcpy(p, HTML_INDEX_FILE);
			fd = open(dirname, O_RDONLY);
#ifdef ALLOW_DIR_LISTINGS
			if (fd < 0) {
				*p = '\0';
				fd = open(dirname, O_RDONLY);
				if (fd >= 0) {
					rc = do_dir(conn, fd, dirname);
					if (rc == 0)
						set_writeable(conn);
					return rc;
				}
			}
#endif
		} else
			fd = open(dirname, O_RDONLY);
	} else /* require an index file at the top level */
		fd = open(HTML_INDEX_FILE, O_RDONLY);

	if (fd < 0)
		return http_error(conn, 404);

	rc = do_file(conn, fd);
	if (rc == 0)
		set_writeable(conn);

	return rc;
}

static int read_request(struct connection *conn)
{
	int n;

	do
		n = read(SOCKET(conn), conn->cmd + conn->offset,
			 MAX_LINE - conn->offset);
	while (n < 0 && errno == EINTR);

	if (n < 0) {
		if (errno == EAGAIN) {
			syslog(LOG_DEBUG, "EAGAIN\n");
			return 0;
		}

		syslog(LOG_WARNING, "Read error (%d): %m", errno);
		close_connection(conn, 408);
		return 1;
	}
	if (n == 0) {
		syslog(LOG_WARNING, "Read: unexpected EOF");
		close_connection(conn, 408);
		return 1;
	}

	conn->offset += n;
	time(&conn->access);

	/* We alloced an extra space for the '\0' */
	conn->cmd[conn->offset] = '\0';

	if (conn->cmd[conn->offset - 1] != '\n') {
		if (conn->offset >= MAX_LINE) {
			syslog(LOG_WARNING, "Line overflow");
			if (strncmp(conn->cmd, "GET ",  4) == 0 ||
			    strncmp(conn->cmd, "HEAD ", 5) == 0)
				return http_error(conn, 414);
			else {
				close_connection(conn, 414);
				return 1;
			}
		}
		return 0; /* not an error */
	}

	if (conn->offset > max_length)
		max_length = conn->offset;

	if (strncmp(conn->cmd, "STATS", 5) == 0)
		return gohttpd_stats(conn);

	if (strncmp(conn->cmd, "GET ",  4) == 0 ||
	    strncmp(conn->cmd, "HEAD ", 5) == 0) {
		/* We must look for \r\n\r\n */
		/* This is mainly for telnet sessions */
		if (strstr(conn->cmd, "\r\n\r\n")) {
			if (verbose > 2)
				printf("Http: %s\n", conn->cmd);
			return http_get(conn);
		}
		conn->http = 1;
		return 0;
	}

	return 1;
}

static int write_request(struct connection *conn)
{
	int n;

	if (conn->n_iovs) {
		do
			n = writev(SOCKET(conn), conn->iovs, conn->n_iovs);
		while (n < 0 && errno == EINTR);

		if (n < 0) {
			if (errno == EAGAIN)
				return 0;

			syslog(LOG_ERR, "writev: %m");
			close_connection(conn, 408);
			return 1;
		}
		if (n == 0) {
			syslog(LOG_ERR, "writev unexpected EOF");
			close_connection(conn, 408);
			return 1;
		}

#ifdef USE_SENDFILE
		/* Normal case only one iov */
		if (unlikely(n < conn->iovs->iov_len)) {
			conn->iovs->iov_len -= n;
			conn->iovs->iov_base += n;
			time(&conn->access);
			return 0;
		}
		conn->n_iovs = 0;
#else
		struct iovec *iov;
		int i;

		for (iov = conn->iovs, i = 0; i < conn->n_iovs; ++i, ++iov)
			if (n >= iov->iov_len) {
				n -= iov->iov_len;
				iov->iov_len = 0;
			} else {
				iov->iov_len -= n;
				iov->iov_base += n;
				time(&conn->access);
				return 0;
			}
#endif
	}

#ifdef USE_SENDFILE
	if (conn->in_fd >= 0) {
		n = sendfile(SOCKET(conn), conn->in_fd,
			     &conn->in_offset, conn->len);
		if (n > 0) {
			set_cork(SOCKET(conn), 0);
			conn->len -= n;
			if (conn->len > 0)
				return 0;
		} else if (n < 0) {
			if (errno == EAGAIN)
				return 0;

			close_connection(conn, 408);
			return 1;
		}
	}
#endif

	close_connection(conn, conn->status);

	return 0;
}

static void setup_privs(void)
{
	/* If you are non-root you cannot set privileges */
	if (getuid())
		return;

	if (uid == (uid_t)-1 || gid == (uid_t)-1) {
		struct passwd *pwd = getpwnam(user);

		if (!pwd)
			fatal_error("No such user: `%s'.", user);
		if (uid == (uid_t)-1)
			uid = pwd->pw_uid;
		if (gid == (uid_t)-1)
			gid = pwd->pw_gid;
		initgroups(pwd->pw_name, pwd->pw_gid);
	}

	setgid(gid);
}

static int listen_socket(int port)
{
	int s, optval;
#ifdef HAVE_INET_NTOP
	struct sockaddr_in6 sock_name;

	memset(&sock_name, 0, sizeof(sock_name));
	sock_name.sin6_family = AF_INET6;
	sock_name.sin6_addr = in6addr_any;
	sock_name.sin6_port = htons(port);

	s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s == -1 && errno == EAFNOSUPPORT) {
		/* fall back to ipv4 */
		sock_name.sin6_family = AF_INET;
		s = socket(AF_INET, SOCK_STREAM, 0);
	}
#else
	struct sockaddr_in sock_name;

	memset(&sock_name, 0, sizeof(sock_name));
	sock_name.sin_family = AF_INET;
	sock_name.sin_addr.s_addr = INADDR_ANY;
	sock_name.sin_port = htons(port);

	s = socket(AF_INET, SOCK_STREAM, 0);
#endif
	if (s == -1)
		return -1;

	optval = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
		       (char *)&optval, sizeof(optval)) == -1 ||
	    bind(s, (struct sockaddr *)&sock_name, sizeof(sock_name)) == -1 ||
	    listen(s, HTTP_BACKLOG) == -1) {
		close(s);
		return -1;
	}

	optval = fcntl(s, F_GETFL, 0);
	if (optval == -1 || fcntl(s, F_SETFL, optval | O_NONBLOCK)) {
		close(s);
		return -1;
	}

	return s;
}

int main(int argc, char *argv[])
{
	char *config = NULL;
	int c, i, n, timeout, go_daemon = 0;
	struct connection *conn;

	while ((c = getopt(argc, argv, "c:dm:v")) != -1)
		switch (c) {
		case 'c':
			config = optarg;
			break;
		case 'd':
			go_daemon = 1;
			break;
		case 'm':
			max_conns = strtol(optarg, NULL, 0);
			break;
		case 'v':
			++verbose;
			break;
		default:
			fatal_error("usage: %s [-dv] [-m max_conns] [-c config]\n", *argv);
		}

	read_config(config);

	if (max_conns == 0)
		max_conns = 25;

	conns = calloc(max_conns, sizeof(struct connection));
	ufds  = calloc(max_conns + 1, sizeof(struct pollfd));
	if (!conns || !ufds)
		fatal_error("Not enough memory. Try reducing max-connections.");

	ufds[0].fd = listen_socket(port);
	ufds[0].events = POLLIN;
	npoll = 1;
	if (ufds[0].fd < 0)
		fatal_error("Unable to create socket: %m");

	for (i = 0; i < max_conns; ++i) {
		conns[i].status = 200;
		conns[i].conn_n = i;
		conns[i].ufd = &ufds[i + 1];
		conns[i].ufd->fd = -1;
	}

	if (go_daemon)
		if (daemon(0, 0) == -1)
			fatal_error("Could not become daemon-process!");

		openlog("gohttpd", LOG_CONS, LOG_DAEMON);

	syslog(LOG_INFO, "gohttpd " GOHTTPD_VERSION " starting.");
	time(&started);

	/* Create *before* chroot */
	create_pidfile(pidfile);

	if (chdir(root_dir))
		fatal_error("%s: %m", root_dir);

	/* Must setup privileges before chroot */
	setup_privs();

	if (do_chroot && chroot(chroot_dir))
		fatal_error("chroot: %m");

	signal(SIGHUP,  sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGINT,  sighandler);
	signal(SIGPIPE, sighandler);
	signal(SIGCHLD, sighandler);

	seteuid(uid);

	/* Now it is safe to install */
	atexit(cleanup);

	log_open(logfile);

	while (1) {
		timeout = n_connections ? (POLL_TIMEOUT * 1000) : -1;
		n = poll(ufds, npoll, timeout);
		if (n < 0) {
			syslog(LOG_WARNING, "poll: %m");
			continue;
		}

		/* Simplistic timeout to start with.
		 * Only check for old connections on a timeout.
		 * Low overhead, but under high load may leave connections
		 * around longer.
		 */
		if (n == 0) {
			check_old_connections();
			continue;
		}

		if (ufds[0].revents) {
			new_connection(ufds[0].fd);
			--n;
		}

		for (conn = conns, i = 0; n > 0 && i < npoll; ++i, ++conn)
			if (conn->ufd->revents & POLLIN) {
				read_request(conn);
				--n;
			} else if (conn->ufd->revents & POLLOUT) {
				write_request(conn);
				--n;
			} else if (conn->ufd->revents) {
				/* Error */
				int status;

				if (conn->ufd->revents & POLLHUP) {
					syslog(LOG_DEBUG, "Connection hung up");
					status = 504;
				} else if (conn->ufd->revents & POLLNVAL) {
					syslog(LOG_DEBUG, "Connection invalid");
					status = 410;
				} else {
					syslog(LOG_DEBUG, "Revents = 0x%x",
					       conn->ufd->revents);
					status = 501;
				}

				close_connection(conn, status);
				--n;
			}
	}
}

/*
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * tab-width: 8
 * End:
 */
