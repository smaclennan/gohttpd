/* config.c - read the config file
 * Copyright (C) 2002-2018  Sean MacLennan <seanm@seanm.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this project; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */
#include <stdarg.h>
#include "gohttpd.h"

char *root_dir;
char *chroot_dir;
char *logfile;
char *pidfile;

int   port = HTTP_PORT;
char *user = HTTP_USER;
uid_t uid  = -1;
gid_t gid  = -1;
int   max_conns     = 25;
int   do_chroot     = -1;

void fatal_error(const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	vsyslog(LOG_ERR, msg, ap);
	va_end(ap);
	puts(msg);
	exit(1);
}

/* If we are already out of memory, we are in real trouble */
static char *must_strdup(char *str)
{
	char *new = strdup(str);

	if (!new)
		fatal_error("read_config: out of memory");
	return new;
}

/* only set if a number specified */
static void must_strtol(char *str, int *value)
{
	char *end;
	long n = strtol(str, &end, 0);

	if (str != end)
		*value = (int)n;
}

void read_config(char *fname)
{
	FILE *fp;
	char line[100];

	if (!fname)
		fname = HTTP_CONFIG;

	/* These values must be malloced */
	user = must_strdup(user);

	fp = fopen(fname, "r");
	if (fp) {
		while (fgets(line, sizeof(line), fp)) {
			if (!isalpha(*line))
				continue;

			char *key = strtok(line, "=");
			char *val = strtok(NULL, "\r\n");

			if (!key || !val)
				fatal_error("Bad line '%s'", line);

			if (strcmp(key, "root") == 0 ||
			    strcmp(key, "root-dir") == 0) {
				if (root_dir)
					free(root_dir);
				root_dir = must_strdup(val);
			} else if (strcmp(key, "chroot-dir") == 0) {
				if (chroot_dir)
					free(chroot_dir);
				chroot_dir = must_strdup(val);
			} else if (strcmp(key, "logfile") == 0) {
				if (logfile)
					free(logfile);
				logfile = must_strdup(val);
			} else if (strcmp(key, "pidfile") == 0) {
				if (pidfile)
					free(pidfile);
				pidfile = must_strdup(val);
			} else if (strcmp(key, "port") == 0)
				must_strtol(val, &port);
			else if (strcmp(key, "user") == 0) {
				if (user)
					free(user);
				user = must_strdup(val);
			} else if (strcmp(key, "uid") == 0)
				must_strtol(val, (int *)&uid);
			else if (strcmp(key, "gid") == 0)
				must_strtol(val, (int *)&gid);
			else if (strcmp(key, "max-connections") == 0)
				must_strtol(val, &max_conns);
			else if (strcmp(key, "chroot") == 0)
				must_strtol(val, &do_chroot);
			else
				fatal_error("Unknown config '%s'", key);
		}

		fclose(fp);
	} else if (errno != ENOENT)
		fatal_error("%s: %m", fname);

	if (do_chroot == -1)
		do_chroot = getuid() == 0;

	/* Default'em */
	if (root_dir == NULL)
		root_dir = must_strdup(HTTP_ROOT);
	if (chroot_dir == NULL)
		chroot_dir = must_strdup(HTTP_CHROOT);
	if (logfile == NULL)
		logfile  =
			must_strdup(do_chroot ? HTTP_LOG_CHROOT : HTTP_LOGFILE);
	if (pidfile == NULL)
		pidfile  = must_strdup(HTTP_PIDFILE);

	if (strlen(root_dir) >= PATH_MAX)
		fatal_error("Root directory too long");

	/* root_dir must be inside chroot_dir */
	if (do_chroot && strncmp(root_dir, chroot_dir, strlen(chroot_dir)))
		fatal_error("%s not inside chroot %s", root_dir, chroot_dir);
}

/*
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * tab-width: 8
 * End:
 */
