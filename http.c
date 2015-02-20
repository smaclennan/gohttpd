/*
 * http.c - http handler
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
 * along with XEmacs; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "gohttpd.h"

/* Does not always return errors */
/* Does not proxy external links */
/* Maybe implement buffering in write_out */

#define MAX_SERVER_STRING	600
static char *server_str;

#define HTML_INDEX_FILE	"index.html"

static int isdir(char *name);

unsigned bad_munmaps;
static unsigned char *mmap_get(struct connection *conn, int fd);

inline int write_out(int fd, char *buf, int len)
{
	return WRITE(fd, buf, len);
}


inline int write_str(int fd, char *str)
{
	return write_out(fd, str, strlen(str));
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


/* This is a very specialized build_response just for errors.
   The request field is for the 301 errors.
*/
static int http_error1(struct connection *conn, int status, char *request)
{
	char str[MAX_LINE + MAX_LINE + MAX_SERVER_STRING + 512];
	char *title, *p, *msg;

	switch (status) {
	case 301:
		/* Be nice and give the moved address. */
		title = "301 Moved Permanently";
		sprintf(str,
			"The document has moved <a href=\"/%s/\">here</a>.",
			request);
		msg = strdup(str);
		if (msg == NULL) {
			syslog(LOG_WARNING, "http_error: Out of memory.");
			close_connection(conn, status);
			return 1;
		}
		break;
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

	sprintf(str,
		"HTTP/1.0 %s\r\n"
		"Server: %s"
		"Content-Type: text/html\r\n",
		title, server_str);

	if (status == 301) {
		/* we must add the *real* location */
		p = str + strlen(str);
		sprintf(p, "Location: /%s/\r\n", request);
	}

	strcat(str, "\r\n");

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

	if (status == 301)
		free(msg);

	conn->http_header = strdup(str);
	if (conn->http_header == NULL) {
		syslog(LOG_WARNING, "http_error: Out of memory.");
		if (status == 302)
			free(msg);
		close_connection(conn, status);
		return 1;
	}

	conn->status = status;

	conn->iovs[0].iov_base = conn->http_header;
	conn->iovs[0].iov_len  = strlen(conn->http_header);
	conn->n_iovs = 1;

	set_writeable(conn);

	return 0;
}


/* For all but 301 errors */
int http_error(struct connection *conn, int status)
{
	return http_error1(conn, status, "bogus");
}


static int http_build_response(struct connection *conn)
{
	char str[1024], *p;

	strcpy(str, "HTTP/1.1 200 OK\r\n");
	strcat(str, server_str);
	/* SAM We do not support persistant connections */
	strcat(str, "Connection: close\r\n");
	p = str;
	p += strlen(p);
	sprintf(p, "Content-Length: %d\r\n\r\n", conn->len);

	conn->http_header = strdup(str);
	if (conn->http_header == NULL) {
		/* Just closing the connection is the best we can do */
		syslog(LOG_WARNING, "Low on memory.");
		close_connection(conn, 500);
		return 1;
	}

	conn->status = 200;

	return 0;
}

static int do_file(struct connection *conn, int fd)
{
	conn->len = lseek(fd, 0, SEEK_END);

	if (http_build_response(conn)) {
		syslog(LOG_WARNING, "Out of memory");
		return -1;
	}

	conn->iovs[0].iov_base = conn->http_header;
	conn->iovs[0].iov_len  = strlen(conn->http_header);

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

#if 0
	struct dirent *ent;
	DIR *dir = fdopendir(fd);

	while ((ent = readdir(dir)))
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

	closedir(dir); /* also closes fd */
#else
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
#endif

	conn->buf = (unsigned char *)strdup(dirbuf);

	if (conn->buf) {
		conn->iovs[1].iov_base = conn->buf;
		conn->iovs[1].iov_len  = n;
	}

	conn->iovs[2].iov_base = (void *)trailer;
	conn->iovs[2].iov_len = strlen(trailer); // SAM

	conn->len = conn->iovs[1].iov_len + conn->iovs[2].iov_len;

	if (http_build_response(conn)) {
		syslog(LOG_WARNING, "Out of memory");
		return -1;
	}

	conn->iovs[0].iov_base = conn->http_header;
	conn->iovs[0].iov_len  = strlen(conn->http_header);
	conn->len += conn->iovs[0].iov_len;

	conn->n_iovs = 3;

	return 0;
}

int http_get(struct connection *conn)
{
	char *e;
	int fd, rc, isfile = 0;
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
				 * URLs will not work */
				return http_error1(conn, 301, request);
			}
			strcpy(p, HTML_INDEX_FILE);
			if ((fd = file_open(dirname)) >= 0)
				isfile = 1;
			else {
				*p = '\0';
				fd = file_open(dirname);
			}
		} else {
			fd = file_open(dirname);
			isfile = 1;
		}
	} else {
		if ((fd = open(HTML_INDEX_FILE, O_RDONLY)) >= 0)
			isfile = 1;
		else {
			strcpy(dirname, "/");
			fd = file_open(".");
		}
	}

	if (fd < 0) {
		syslog(LOG_WARNING, "%s: %m", request);
		return http_error(conn, 404);
	}

	if (isfile)
		rc = do_file(conn, fd);
	else
		rc = do_dir(conn, fd, dirname);

	if (rc == 0)
		set_writeable(conn);

	return rc;
}


static int isdir(char *name)
{
	struct stat sbuf;

	if (stat(name, &sbuf) == -1)
		return 0;
	return S_ISDIR(sbuf.st_mode);
}


int http_init(void)
{
	char str[600];
	struct utsname uts;

	uname(&uts);

	sprintf(str, "Server: gohttpd/%.8s (%.512s)\r\n",
		GOHTTPD_VERSION, uts.sysname);

	server_str = strdup(str);
	if (!server_str) {
		syslog(LOG_ERR, "http_init: Out of memory");
		exit(1);
	}

	return 0;
}


void http_cleanup(void)
{
	if (server_str)
		free(server_str);
}

/* added by folkert@vanheusden.com */
/* This function takes away all the hassle when working
 * with read(). Blocking reads only.
 */
int READ(int handle, char *whereto, int len)
{
	int cnt = 0;

	while (1) {
		int rc;

		rc = read(handle, whereto, len);

		if (rc == -1) {
			if (errno != EINTR) {
				syslog(LOG_DEBUG,
				       "READ(): io-error [%d - %s]",
				       errno, strerror(errno));
				return -1;
			}
		} else if (rc == 0)
			return cnt;
		else {
			whereto += rc;
			len -= rc;
			cnt += rc;
		}
	}

	return cnt;
}


/* added by folkert@vanheusden.com */
/* this function takes away all the hassle when working
 * with write(). Blocking writes only.
 */
int WRITE(int handle, char *whereto, int len)
{
	int cnt = 0;

	while (len > 0) {
		int rc;

		rc = write(handle, whereto, len);

		if (rc == -1) {
			if (errno != EINTR) {
				syslog(LOG_DEBUG,
				       "WRITE(): io-error [%d - %s]",
				       errno, strerror(errno));
				return -1;
			}
		} else if (rc == 0)
			return cnt;
		else {
			whereto += rc;
			len -= rc;
			cnt += rc;
		}
	}

	return cnt;
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

void mmap_release(struct connection *conn)
{
	if (munmap(conn->buf, conn->mapped)) {
		++bad_munmaps;
		syslog(LOG_ERR, "munmap %p %d", conn->buf, conn->mapped);
	}
}
