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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <assert.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <pwd.h>
#include <grp.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "gohttpd.h"

int verbose;

/* Stats */
static unsigned max_requests;
static unsigned max_length;
static unsigned n_requests;
static int      n_connections; /* yes signed, I want to know if it goes -ve */
static time_t   started;

/* Add an extra connection for error replies */
static struct connection *conns;

static struct pollfd *ufds;
static int npoll;

static uid_t root_uid;

/* forward references */
static void gohttpd(char *name);
static void create_pidfile(char *fname);
static int new_connection(int csock);
static int read_request(struct connection *conn);
static int write_request(struct connection *conn);
static int gohttpd_stats(struct connection *conn);
static void check_old_connections(void);


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

	http_cleanup();

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
	free(hostname);
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
			printf("usage: %s [-dpv] [-m max_conns] [-c config]\n",
			       *argv);
			exit(1);
		}

	if (read_config(config))
		exit(1);

	if (max_conns == 0)
		max_conns = 25;

	conns = calloc(max_conns, sizeof(struct connection));
	if (!conns) {
		syslog(LOG_CRIT, "Not enough memory."
		       " Try reducing max-connections.");
		exit(1);
	}

	http_init();

	if (go_daemon) {
		if (daemon(0, 0) == -1)
			syslog(LOG_CRIT, "Could not become daemon-process!");
		else
			gohttpd(prog); /* never returns */
	} else
		gohttpd(prog); /* never returns */

	return 1;
}

static void setup_privs(void)
{
	root_uid = getuid();

	/* If you are non-root you cannot set privileges */
	if (root_uid) return;

	if (uid == (uid_t)-1 || gid == (uid_t)-1) {
		struct passwd *pwd = getpwnam(user);
		if (!pwd) {
			syslog(LOG_ERR, "No such user: `%s'.", user);
			closelog();
			exit(1);
		}
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

	if (chdir(root_dir)) {
		perror(root_dir);
		exit(1);
	}

	setup_privs();

	/* Do this *before* chroot */
	log_open(logfile);

	if (do_chroot == -1)
		do_chroot = getuid() == 0;
	if (do_chroot && chroot(root_dir)) {
		perror("chroot");
		exit(1);
	} else
		syslog(LOG_WARNING, "No chroot.");

	signal(SIGHUP,  sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGINT,  sighandler);
	signal(SIGPIPE, sighandler);
	signal(SIGCHLD, sighandler);

	/* connection socket */
	csock = listen_socket(port);
	if (csock < 0) {
		syslog(LOG_ERR, "Unable to create socket: %m");
		exit(1);
	}

	seteuid(uid);

	for (i = 0; i < max_conns; ++i) {
		conns[i].status = 200;
		conns[i].conn_n = i;
		alloc_sock_addr(&conns[i]);
	}

	ufds = calloc(max_conns + 1, sizeof(struct pollfd));
	if (!ufds) {
		syslog(LOG_CRIT, "Not enough memory."
		       " Try reducing max-connections.");
		exit(1);
	}

	for (i = 0; i < max_conns; ++i) {
		conns[i].ufd = &ufds[i + 1];
		conns[i].ufd->fd = -1;
	}

	/* Now it is safe to install */
	atexit(cleanup);

	main_loop(csock);
}


#ifdef ALLOW_NON_ROOT
static int checkpath(char *path)
{
#if 0
	/* This does not work in a chroot environment */
	char full[PATH_MAX + 2];
	char real[PATH_MAX + 2];
	int  len = strlen(root_dir);

	strcpy(full, root_dir);
	strcat(full, "/");
	strncat(full, path, PATH_MAX - len);
	full[PATH_MAX] = '\0';

	if (!realpath(full, real))
		return 1;

	if (strncmp(real, root_dir, len)) {
		errno = EACCES;
		return -1;
	}
#else
	/* A .. at the end is safe since it will never specify a file,
	 * only a directory. */
	if (strncmp(path, "../", 3) == 0 || (int)strstr(path, "/../")) {
		errno = EACCES;
		return -1;
	}
#endif

	return 0;
}
#endif


void close_connection(struct connection *conn, int status)
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

	if (conn->http_header) {
		free(conn->http_header);
		conn->http_header = NULL;
	}
	conn->http = 0;
	conn->referer = NULL;
	conn->user_agent = NULL;

	conn->status = 200;

	memset(conn->iovs, 0, sizeof(conn->iovs));

	ufds[0].events = POLLIN; /* in case we throttled */
}


static int new_connection(int csock)
{
	int sock;
	int i;
	struct connection *conn;

	seteuid(root_uid);

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
			if (kill(pid, 0) == 0) {
				syslog(LOG_ERR,
				       "gohttpd already running (pid = %d)",
				       pid);
				exit(1);
			}
		} else {
			syslog(LOG_ERR, "Unable to read %s", fname);
			exit(1);
		}
	} else if (errno != ENOENT) {
		syslog(LOG_ERR, "Open %s: %m", fname);
		exit(1);
	}

	if ((fp = fopen(fname, "w"))) {
		pid = getpid();
		fprintf(fp, "%d\n", pid);
		fclose(fp);
	} else  if (errno != EACCES) {
		syslog(LOG_ERR, "Create %s: %m", fname);
		exit(1);
	}
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
			 "Max length:   %10u\r\n"
			 "Connections:  %10d\r\n",
			 uptime(up, sizeof(up)),
			 n_requests,
			 max_requests, max_length,
			 /* we are an outstanding connection */
			 n_connections - 1);

	if (bad_munmaps)
		snprintf(buf + n, sizeof(buf) - n, "BAD UNMAPS:   %10u\r\n", bad_munmaps);

	while (write(SOCKET(conn), buf, strlen(buf)) < 0 && errno == EINTR)
		;

	close_connection(conn, 1000);

	return 0;
}
