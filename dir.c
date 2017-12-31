/* dir.c - optional directory listings
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

#ifdef ALLOW_DIR_LISTINGS
#ifdef USE_SENDFILE
#error ALLOW_DIR_LISTINGS does not support sendfile
#endif

/* SAM HACK FOR NOW */
static char dirbuf[16 * 1024];

static const char *header =
	"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n"
	"<html lang=\"en\">\n"
	"<head><title>Index of %s</title>\n"
	"<body>\n<h2>Index of %s</h2><hr>\n";

static const char *trailer = "<hr>\n</body></html>\n";

int do_dir(struct connection *conn, int fd, const char *dirname)
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
	conn->status = 200;

	conn->iovs[0].iov_base = conn->http_header;
	conn->iovs[0].iov_len  = snprintf(conn->http_header,
					  sizeof(conn->http_header),
					  "HTTP/1.1 200 OK\r\n"
					  SERVER_STR
					  "Connection: close\r\n"
					  "Content-Length: %d\r\n\r\n",
					  conn->len);

	conn->len += conn->iovs[0].iov_len;

	conn->n_iovs = 3;

	return 0;
}
#endif

/*
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * tab-width: 8
 * End:
 */