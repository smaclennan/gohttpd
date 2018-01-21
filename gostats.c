#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>

/* Trivial program to get stats from gohttpd where you don't have (or
 * more likely aren't allowed to have for security reasons) telnet or
 * netcat.
 */

int main(int argc, char *argv[])
{
	struct sockaddr_in sock_name;
	struct hostent *host;
	char *p, *hostname = "localhost";
	int port = 80;

	if (argc > 1) {
		hostname = argv[1];
		if ((p = strchr(hostname, ':'))) {
			*p++ = 0;
			port = strtol(p, NULL, 10);
		}
	}

	if (!(host = gethostbyname(hostname))) {
		printf("Unable to get host %s\n", hostname);
		exit(1);
	}

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1)
		goto failed;

	/* optimization - we don't care if it fails */
	int flags = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));

	memset(&sock_name, 0, sizeof(sock_name));
	sock_name.sin_family = AF_INET;
	sock_name.sin_addr.s_addr = *(unsigned *)host->h_addr_list[0];
	sock_name.sin_port = htons((short)port);

	if (connect(sock, (struct sockaddr *)&sock_name, sizeof(sock_name)))
		goto failed;

	if (write(sock, "STATS\r\n", 7) != 7)
		goto failed;

	/* We should always be able to read in one go... */
	char buf[256];
	int n;
	if ((n = read(sock, buf, sizeof(buf) - 1)) <= 0)
		goto failed;

	close(sock);

	buf[n] = 0;
	fputs(buf, stdout);

	return 0;

failed:
	if (sock >= 0)
		close(sock);
	perror("connect");
	exit(1);
}
