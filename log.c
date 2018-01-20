/* log.c - log file output
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


static FILE *log_fp;
static int need_reopen;

static void sig_reopen(int sig)
{
	need_reopen = 1;
}

static void log_reopen(void)
{
	if (log_fp) {
		fclose(log_fp);

		log_fp = fopen(logfile, "a");
		if (log_fp == NULL)
			syslog(LOG_ERR, "Reopen %s: %m", logfile);
		else
			syslog(LOG_WARNING, "Log file reopened.");
	}
}

int log_open(void)
{
	log_fp = fopen(logfile, "a");
	if (log_fp == NULL)
		fatal_error("Unable to open %s: %m", logfile);

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

/* Combined log file format */
void log_hit(struct connection *conn)
{
	char date[32];

	if (need_reopen) {
		log_reopen();
		need_reopen = 0;
	}

	if (!log_fp)
		return; /* nowhere to write! */

	if (conn->status == 1000)
		return; /* don't log stat calls */

	/* We must use localtime_r()... localtime will reset the
	 * timezone to UTC in a chroot jail.
	 */
	struct tm result;
	time_t now = time(NULL);
	strftime(date, sizeof(date), "[%d/%b/%Y:%T %z]", localtime_r(&now, &result));

	char *referer = trim_str(conn->referer, 8);
	char *agent = trim_str(conn->user_agent, 12);

	while (fprintf(log_fp,
		       "%s - - %s \"%.200s\" %u %u \"%.100s\" \"%.100s\"\n",
		       ntoa(conn), date, conn->cmd, conn->status, conn->len,
		       referer, agent) < 0 && errno == EINTR) ;

	fflush(log_fp);
}


/*
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * tab-width: 8
 * End:
 */
