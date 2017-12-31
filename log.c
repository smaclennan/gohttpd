/*
 * log.c - log file output
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
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>

#include "gohttpd.h"


/* #define LOG_HIT_DBG 1 */

static FILE *log_fp;
static char *log_name;
static int need_reopen;

static void sig_reopen(int sig)
{
	need_reopen = 1;
}

static void log_reopen(void)
{
	if (log_fp) {
		fclose(log_fp);

		log_fp = fopen(log_name, "a");
		if (log_fp == NULL)
			syslog(LOG_ERR, "Reopen %s: %m", log_name);

		syslog(LOG_WARNING, "Log file reopened.");
	}
}

int log_open(char *logname)
{
	log_fp = fopen(logname, "a");
	if (log_fp == NULL)
		fatal_error("Unable to open %s: %m", logname);

	if (fchown(fileno(log_fp), uid, gid))
		perror("chown log file");

	signal(SIGUSR1, sig_reopen);

	return 1;
}

/* Warning: This is destructive to str */
static char *trim_str(char *str, int skip)
{
	char *p;

	if (!str)
		return "-";

	str += skip;

	while (isspace(*str))
			++str;
	p = strpbrk(str, "\r\n");
	if (p)
		*p = '\0';
	else
		return "-";

	return str;
}

static void add_combined_log(struct connection *conn,
			     char *common, char *request, unsigned status)
{	/* This is 500 + hostname chars max */
	char *referer, *agent;
	int n;

	referer = trim_str(conn->referer, 8);
	agent = trim_str(conn->user_agent, 12);

	do {
		n = fprintf(log_fp,
			    "%s /%.200s\" %u %u \"%.100s\" "
			    "\"%.100s\"\n",
			    common, request, status, conn->len,
			    referer, agent);
	} while (n < 0 && errno == EINTR);
}

#ifdef LOG_HIT_DBG
static unsigned logcnt;
#endif

/* Common log file format */
void log_hit(struct connection *conn, unsigned status)
{
	char common[100], *p = common;
	time_t now;
	struct tm *t;
	int n, len = sizeof(common);

	if (!log_fp)
		return; /* nowhere to write! */

	if (need_reopen) {
		log_reopen();
		need_reopen = 0;
	}

	time(&now);
	t = localtime(&now);

	/* Get some of the fixed length common stuff out of the way */
	n = snprintf(p, len, "%s", ntoa(conn));
	p += n;
	len -= n;
#ifdef LOG_HIT_DBG
	n = snprintf(p, len, " - %u ", logcnt++);
	p += n;
	len -= n;
	n = strftime(p, len, "[%d/%b/%Y:%T %z] \"", t);
#else
	n = strftime(p, len, " - - [%d/%b/%Y:%T %z] \"", t);
#endif
	p += n;
	len -= n;
	snprintf(p, len, "%s", conn->http == HTTP_HEAD ? "HEAD" : "GET");

	char *request;

	/* SAM Save this? */
	request = conn->cmd;
	request += 4;
	while (isspace((int)*request))
		++request;
	if (*request == '/')
		++request;

	add_combined_log(conn, common, request, status);

	fflush(log_fp);
}


void log_close(void)
{
	if (log_fp) {
		(void)fclose(log_fp);
		log_fp = NULL;
	}
}
