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
#include "gohttpd.h"

#ifdef ALLOW_DIR_LISTINGS
#include <dirent.h>

/* SAM HACK FOR NOW */
static char dirbuf[64 * 1024];

static const char *header =
	"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n"
	"<html lang=\"en\">\n"
	"<head>\n"
	"<meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">\n"
	"<style>body { margin: 1em 10% 0 10%; font-size: medium; }</style>\n"
	"<title>Index of %s</title>\n"
	"</head>\n"
	"<body bgcolor=\"#C0C0C0\">"
	"<h1>Index of %s</h1>\n"
	"<hr>\n";

#define TRAILER "<hr>\n</body></html>\n"

/* These need to point at a stable place in your website */
#define DIR_IMAGE "/real/images/gopher_menu.gif"
#define IMG_IMAGE "/real/images/gopher_image.gif"
#define TXT_IMAGE "/real/images/gopher_text.gif"

static int is_image(const char *fname)
{
	static const char *exts[] = { "gif", "jpg", "jpeg", "png", NULL };

	char *p = strrchr(fname, '.');
	if (p) {
		char ext[8];
		int i;

		for (++p, i = 0; *p && i < 7; ++i, ++p)
			ext[i] = tolower(*p);
		ext[i] = '\0';

		for (i = 0; exts[i]; ++i)
			if (strcmp(exts[i], ext) == 0)
				return 1;
	}

	return 0;
}

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
						      "<a href=\"%s/\">"
						      "<img src=\"" DIR_IMAGE "\" "
						      "width=24 height=23 alt=\"Dir\">"
						      "%s/</a><br>\n", ent->d_name, ent->d_name);
				else if (is_image(ent->d_name))
					n += snprintf(dirbuf + n, sizeof(dirbuf) - n,
						      "<a href=\"%s\">"
						      "<img src=\"" IMG_IMAGE "\" "
						      "width=24 height=23 alt=\"File\">"
						      "%s</a><br>\n", ent->d_name, ent->d_name);
				else
					n += snprintf(dirbuf + n, sizeof(dirbuf) - n,
						      "<a href=\"%s\">"
						      "<img src=\"" TXT_IMAGE "\" "
						      "width=24 height=23 alt=\"File\">"
						      "%s</a><br>\n", ent->d_name, ent->d_name);
			}
			else perror(path); // SAM DBG
		}
		free(namelist[i]);
	}

	// printf("Dir size %d\n", n); // SAM DBG

	free(namelist);

	conn->dirbuf = strdup(dirbuf);
	if (!conn->dirbuf) {
		http_error(conn, 503);
		return ENOMEM;
	}

	conn->iovs[1].iov_base = conn->dirbuf;
	conn->iovs[1].iov_len  = n;

	conn->iovs[2].iov_base = TRAILER;
	conn->iovs[2].iov_len  = sizeof(TRAILER) - 1;

	conn->len = conn->iovs[1].iov_len + conn->iovs[2].iov_len;

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
	conn->status = 200;

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
