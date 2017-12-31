/*
 * socket.c - socket utilities
 * Copyright (C) 2015  Sean MacLennan <seanm@seanm.ca>
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
/*
 * All knowledge of sockets should be isolated to this file.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "gohttpd.h"

#ifndef HAVE_INET_NTOP
#define IPV4_ONLY
#endif


int listen_socket(int port)
{
	int s, optval;
#ifdef IPV4_ONLY
	struct sockaddr_in sock_name;

	memset(&sock_name, 0, sizeof(sock_name));
	sock_name.sin_family = AF_INET;
	sock_name.sin_addr.s_addr = INADDR_ANY;
	sock_name.sin_port = htons(port);
	optval = 1;

	s = socket(AF_INET, SOCK_STREAM, 0);
#else
	struct sockaddr_in6 sock_name;

	memset(&sock_name, 0, sizeof(sock_name));
	sock_name.sin6_family = AF_INET6;
	sock_name.sin6_addr = in6addr_any;
	sock_name.sin6_port = htons(port);

	s = socket(AF_INET6, SOCK_STREAM, 0);
#endif
	if (s == -1)
		return -1;

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

int accept_socket(int sock, struct connection *conn)
{
	int new, flags;
#ifdef IPV4_ONLY
	unsigned addrlen = sizeof(struct sockaddr_in);
#else
	unsigned addrlen = sizeof(struct sockaddr_storage);
#endif
	new = accept(sock, conn->sock_addr, &addrlen);
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


void alloc_sock_addr(struct connection *conn)
{
#ifdef IPV4_ONLY
	conn->sock_addr = malloc(sizeof(struct sockaddr_in));
#else
	conn->sock_addr = malloc(sizeof(struct sockaddr_storage));
#endif
	if (!conn->sock_addr)
		fatal_error("Out of memory");
}

void set_cork(int sock, int on)
{	/* Optimization - not an error if it fails */
#if defined(TCP_NOPUSH) && !defined(TCP_CORK)
#define TCP_CORK TCP_NOPUSH
#endif
	setsockopt(sock, IPPROTO_TCP, TCP_CORK, &on, sizeof(on));
}

/* network byte order */
const char *ntoa(struct connection *conn)
{
#ifdef IPV4_ONLY
	struct sockaddr_in *sin = conn->sock_addr;
	return inet_ntoa(sin->sin_addr);
#else
	static char a[64];
	struct sockaddr_storage *sin = conn->sock_addr;
	return inet_ntop(sin->ss_family, sin, a, sizeof(a));
#endif
}
