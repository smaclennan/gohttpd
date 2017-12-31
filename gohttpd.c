/*
 * gohttpd.c - the mainline for the go httpd
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
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "gohttpd.h"

static int verbose;

/* Stats */
static unsigned max_requests;
static unsigned max_length;
static unsigned n_requests;
static int      n_connections; /* yes signed, I want to know if it goes -ve */
static time_t   started;

static struct connection *conns;

static struct pollfd *ufds;
static int npoll;

#define HTML_INDEX_FILE	"index.html"

unsigned bad_munmaps;

/* forward references */
static void gohttpd(char *name);
static void create_pidfile(char *fname);
static int new_connection(int csock);
static int read_request(struct connection *conn);
static int write_request(struct connection *conn);
static int gohttpd_stats(struct connection *conn);
static void check_old_connections(void);
static unsigned char *mmap_get(struct connection *conn, int fd);
static void mmap_release(struct connection *conn);
static int http_get(struct connection *conn);
static int http_error(struct connection *conn, int status);
static void close_connection(struct connection *conn, int status);

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
		 * connection on us. */
		break;
	default:
		syslog(LOG_WARNING, "Got an unexpected %d signal\n", signum);
		break;
	}
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
	for (conn = conns, i = 0; i < max_conns; ++i, ++conn) {
		if (SOCKET(conn) != -1)
			close_connection(conn, 500);
		if (conn->cmd)
			free(conn->cmd);
		free(conn->sock_addr);
	}

	free(user);
	free(root_dir);
	free(logfile);
	free(pidfile);

	free(conns);
	free(ufds);

	closelog();
}

int main(int argc, char *argv[])
{
	char *config = NULL;
	int c, go_daemon = 0;
	char *prog;

	prog = strrchr(argv[0], '/');
	if (prog)
		++prog;
	else
		prog = argv[0];

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
			fatal_error("usage: %s [-dpv] [-m max_conns] [-c config]\n", *argv);
		}

	read_config(config);

	if (max_conns == 0)
		max_conns = 25;

	conns = calloc(max_conns, sizeof(struct connection));
	if (!conns)
		fatal_error("Not enough memory. Try reducing max-connections.");

	if (go_daemon) {
		if (daemon(0, 0) == -1)
			fatal_error("Could not become daemon-process!");
		else
			gohttpd(prog); /* never returns */
	} else
		gohttpd(prog); /* never returns */

	return 1;
}

static void setup_privs(void)
{
	/* If you are non-root you cannot set privileges */
	if (getuid()) return;

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

static void main_loop(int csock)
{
	struct connection *conn;
	int i, n;
	int timeout;

	ufds[0].fd = csock;
	ufds[0].events = POLLIN;
	npoll = 1;

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

		if (n > 0)
			syslog(LOG_DEBUG, "Not all requests processed");
	}
}

static void gohttpd(char *name)
{
	int csock, i;

	openlog(name, LOG_CONS, LOG_DAEMON);
	syslog(LOG_INFO, "gohttpd " GOHTTPD_VERSION " (%s) starting.", name);
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

	/* connection socket */
	csock = listen_socket(port);
	if (csock < 0)
		fatal_error("Unable to create socket: %m");

	seteuid(uid);

	for (i = 0; i < max_conns; ++i) {
		conns[i].status = 200;
		conns[i].conn_n = i;
		alloc_sock_addr(&conns[i]);
	}

	ufds = calloc(max_conns + 1, sizeof(struct pollfd));
	if (!ufds)
		fatal_error("Not enough memory. Try reducing max-connections.");

	for (i = 0; i < max_conns; ++i) {
		conns[i].ufd = &ufds[i + 1];
		conns[i].ufd->fd = -1;
	}

	/* Now it is safe to install */
	atexit(cleanup);

	/* Do this after chroot but before seteuid */
	log_open(logfile);

	main_loop(csock);
}

static void close_connection(struct connection *conn, int status)
{
	if (verbose > 2)
		printf("Close request\n");

	--n_connections;

	if (conn->cmd) {
		/* Make we have a clean cmd */
		char *p;

		for (p = conn->cmd; *p && *p != '\r' && *p != '\n'; ++p)
			;
		*p = '\0';

		if (strncmp(conn->cmd, "GET ", 4) == 0 ||
		    strncmp(conn->cmd, "HEAD ", 5) == 0)
			conn->http = 1;
	}

	/* Log hits in one place. Do not log stat requests. */
	if (status != 1000)
		log_hit(conn, status);

	if (conn->conn_n > MIN_REQUESTS && conn->cmd) {
		free(conn->cmd);
		conn->cmd = NULL;
	}

	if (conn->buf) {
		if (conn->mapped)
			mmap_release(conn);
		else
			free(conn->buf);
		conn->buf = NULL;
	}

	conn->len = conn->offset = conn->mapped = 0;

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
#ifdef ADD_301_SUPPORT
	if (conn->errorstr) {
		free(conn->errorstr);
		conn->errorstr = NULL;
	}
#endif

	conn->status = 200;

	memset(conn->iovs, 0, sizeof(conn->iovs));

	ufds[0].events = POLLIN; /* in case we throttled */
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
		conn->mapped = 0;
		time(&conn->access);

		if (!conn->cmd) {
			conn->cmd = malloc(MAX_LINE + 1);
			if (!conn->cmd) {
				syslog(LOG_WARNING, "Out of memory.");
				close_connection(conn, 503);
			}
		}
	}
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

	if (strcmp(conn->cmd, "STATS\r\n") == 0)
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
	int n, i;
	struct iovec *iov;

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

	close_connection(conn, conn->status);

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
				fatal_error("gohttpd already running (pid = %d)", pid);
		} else
			fatal_error("Unable to read %s", fname);
	} else if (errno != ENOENT)
		fatal_error("Open %s: %m", fname);

	if ((fp = fopen(fname, "w"))) {
		pid = getpid();
		fprintf(fp, "%d\n", pid);
		fclose(fp);
	} else  if (errno != EACCES)
		fatal_error("Create %s: %m", fname);
}

#define SECONDS_IN_A_MINUTE	(60)
#define SECONDS_IN_AN_HOUR	(SECONDS_IN_A_MINUTE * 60)
#define SECONDS_IN_A_DAY	(SECONDS_IN_AN_HOUR * 24)

static char *uptime(char *str, int len)
{
	time_t up = time(NULL) - started;

	if (up >= SECONDS_IN_A_DAY) {
		up /= SECONDS_IN_A_DAY;
		snprintf(str, len, "%ld %s", up, up == 1 ? "day" : "days");
	} else if (up >= SECONDS_IN_AN_HOUR) {
		up /= SECONDS_IN_AN_HOUR;
		snprintf(str, len, "%ld %s", up, up == 1 ? "hour" : "hours");
	} else
		snprintf(str, len, "< 1 hour");

	return str;
}

static int gohttpd_stats(struct connection *conn)
{
	char buf[200], up[12];
	int n;

	n = snprintf(buf, sizeof(buf),
				 "gohttpd " GOHTTPD_VERSION " %12s\r\n"
				 "Requests:     %10u\r\n"
				 "Max parallel: %10u\r\n"
				 "Max length:   %10u\r\n",
				 uptime(up, sizeof(up)),
				 n_requests,
				 max_requests, max_length);

	if (bad_munmaps)
		snprintf(buf + n, sizeof(buf) - n, "BAD UNMAPS:   %10u\r\n", bad_munmaps);

	while (write(SOCKET(conn), buf, strlen(buf)) < 0 && errno == EINTR)
		;

	close_connection(conn, 1000);

	return 0;
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


static char *msg_400 =
	"Your browser sent a request that this server could not understand.";

static char *msg_404 =
	"The requested URL was not found on this server.";

static char *msg_414 =
	"The requested URL was too large.";

static char *msg_500 =
	"An internal server error occurred. Try again later.";


#ifdef ADD_301_SUPPORT
/* This is a very specialized build_response just for errors.
   The request field is for the 301 errors.
*/
static int http_error301(struct connection *conn, char *request)
{
	char str[MAX_LINE + MAX_LINE + MAX_SERVER_STRING + 512];
	char *title, *p, *msg;

	/* Be nice and give the moved address. */
	title = "301 Moved Permanently";
	sprintf(str,
			"The document has moved <a href=\"/%s/\">here</a>.",
			request);
	msg = strdup(str);
	if (msg == NULL) {
		syslog(LOG_WARNING, "http_error: Out of memory.");
		close_connection(conn, 301);
		return 1;
	}

	sprintf(str,
			"HTTP/1.0 %s\r\n"
			SERVER_STR
			"Content-Type: text/html\r\n"
			"Location: /%s/\r\n\r\n",
			title, request);

	/* Build the html body */
	p = str + strlen(str);
	sprintf(p,
		"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
		"<html lang=\"en\">\n<head>\n"
		"<title>%s</title>\r\n"
		"</head>\n<body><h1>%s</h1>\r\n"
		"<p>%s\r\n"
		"</body></html>\r\n",
		title, title, msg);

	free(msg);

	conn->errorstr = strdup(str);
	if (conn->errorstr == NULL) {
		syslog(LOG_WARNING, "http_error: Out of memory.");
		free(msg);
		close_connection(conn, 301);
		return 1;
	}

	conn->status = 301;

	conn->iovs[0].iov_base = conn->errorstr;
	conn->iovs[0].iov_len  = strlen(conn->errorstr);
	conn->n_iovs = 1;

	set_writeable(conn);

	return 0;
}
#endif

/* For all but 301 errors */
int http_error(struct connection *conn, int status)
{
	char *title, *msg;
	int n1, n2;

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
				  "HTTP/1.0 %s\r\n"
				  SERVER_STR
				  "Content-Type: text/html\r\n\r\n",
				  title);

	/* Build the html body */
	n2 = snprintf(conn->tmp_buf, sizeof(conn->tmp_buf),
				  "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
				  "<html lang=\"en\">\n<head>\n"
				  "<title>%s</title>\r\n"
				  "</head>\n<body><h1>%s</h1>\r\n"
				  "<p>%s\r\n"
				  "</body></html>\r\n",
				  title, title, msg);

	conn->status = status;

	conn->iovs[0].iov_base = conn->http_header;
	conn->iovs[0].iov_len  = n1;
	conn->iovs[1].iov_base = conn->tmp_buf;
	conn->iovs[1].iov_len  = n2;
	conn->n_iovs = 2;

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
	conn->len = lseek(fd, 0, SEEK_END);

	conn->iovs[0].iov_base = conn->http_header;
	conn->iovs[0].iov_len  = http_build_response(conn);

	if (conn->http == HTTP_HEAD) {
		/* no body to send */
		close(fd);

		conn->len = 0;
		conn->n_iovs = 1;

		return 0;
	}

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

	return 0;
}

#ifdef ALLOW_DIR_LISTINGS
/* SAM HACK FOR NOW */
static char dirbuf[16 * 1024];

static const char *header =
	"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n"
	"<html lang=\"en\">\n"
	"<head><title>Index of %s</title>\n"
	"<body>\n<h2>Index of %s</h2><hr>\n";

static const char *trailer = "<hr>\n</body></html>\n";

static int do_dir(struct connection *conn, int fd, const char *dirname)
{
	int n;
	struct stat sbuf;
	char path[1024];

	n = snprintf(dirbuf, sizeof(dirbuf), header, dirname, dirname);

	if (strcmp(dirname, "/"))
		n += snprintf(dirbuf + n, sizeof(dirbuf) - n,
					  "<a href=\"../\">Parent Directory/</a><br>\n");

	close(fd);

	struct dirent **namelist, *ent;
	int i, n_files;

	if (strcmp(dirname, "/") == 0)
		n_files = scandir(".", &namelist, NULL, alphasort);
	else
		n_files = scandir(dirname, &namelist, NULL, alphasort);
	if (n_files < 0) {
		perror("scandir");
		return 1;
	}

	for (i = 0; i < n_files; ++i) {
		ent = namelist[i];
		if (*ent->d_name != '.') {
			if (*(dirname + 1))
				snprintf(path, sizeof(path), "%s%s", dirname, ent->d_name);
			else
				snprintf(path, sizeof(path), "%s", ent->d_name);
			if (stat(path, &sbuf) == 0) {
				if (S_ISDIR(sbuf.st_mode))
					n += snprintf(dirbuf + n, sizeof(dirbuf) - n,
								  "<a href=\"%s/\">%s/</a><br>\n",
								  ent->d_name, ent->d_name);
				else
					n += snprintf(dirbuf + n, sizeof(dirbuf) - n,
								  "<a href=\"%s\">%s</a><br>\n",
								  ent->d_name, ent->d_name);
			}
			else perror(path); // SAM DBG
		}
		free(namelist[i]);
	}

	free(namelist);

	conn->buf = (unsigned char *)strdup(dirbuf);

	if (conn->buf) {
		conn->iovs[1].iov_base = conn->buf;
		conn->iovs[1].iov_len  = n;
	}

	conn->iovs[2].iov_base = (void *)trailer;
	conn->iovs[2].iov_len = strlen(trailer); // SAM

	conn->len = conn->iovs[1].iov_len + conn->iovs[2].iov_len;

	conn->iovs[0].iov_base = conn->http_header;
	conn->iovs[0].iov_len  = http_build_response(conn);
	conn->len += conn->iovs[0].iov_len;

	conn->n_iovs = 3;

	return 0;
}
#endif

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
#ifdef ADD_301_SUPPORT
			if (*(p - 1) != '/') {
				/* We must send back a 301
				 * response or relative
				 * URLs will not work */
				return http_error301(conn, request);
			}
#endif
			strcpy(p, HTML_INDEX_FILE);
#ifdef ALLOW_DIR_LISTINGS
			if ((fd = open(dirname, O_RDONLY)) < 0) {
				*p = '\0';
				fd = open(dirname, O_RDONLY);
				if (fd >= 0) {
					rc = do_dir(conn, fd, dirname);
					if (rc == 0)
						set_writeable(conn);
					return rc;
				}
			}
#else
			fd = open(dirname, O_RDONLY);
#endif
		} else
			fd = open(dirname, O_RDONLY);
	} else /* require an index file at the top level */
		fd = open(HTML_INDEX_FILE, O_RDONLY);

	if (fd < 0) {
		syslog(LOG_WARNING, "%s: %m", request);
		return http_error(conn, 404);
	}

	rc = do_file(conn, fd);
	if (rc == 0)
		set_writeable(conn);

	return rc;
}

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
	if (munmap(conn->buf, conn->mapped)) {
		++bad_munmaps;
		syslog(LOG_ERR, "munmap %p %d", conn->buf, conn->mapped);
	}
}
