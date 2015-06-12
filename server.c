#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>
#include "dns.h"

#define BUFFER_LEN 512

struct dnsServer
{
	uint16_t 		port;
	struct sockaddr_in	server,
				client;
	int32_t			sock;
	int8_t			buffer[BUFFER_LEN];
};

int die(const char *msg, int code)
{
	fprintf(stderr, "%s\n", msg);
	return code;
}

int handleRequest(struct dnsServer *srv, int len)
{
	struct DNSHeader head;
	struct DNSQuestion question;
	struct DNSAnswer answer;
	int8_t *ptr = srv->buffer;
	char *addr, *buf = NULL;
	uint16_t size;
	ptr = readDNSHeader(&head, ptr);
	ptr = readDNSQuestion(&question, ptr);
	if (question.qtype != 1) //handle only A requests
	{
		fprintf(stderr, "QUESTION TYPE 0x%x\n", question.qtype);
		return -1; //call passthrough
	}
	else if ((addr = resolveHost(question.qname)) == NULL) //call passthrough
		return die("COULD NOT RESOLVE", -1);
	else
	{
		printf("Received packet from %s:%d\n",
			inet_ntoa(srv->client.sin_addr), ntohs(srv->client.sin_port));
		printf("NAME TO RESOLVE: %s\t%s\n", question.qname, addr);
		answer = createDNSAnswer(&question, addr);
		createDNSResponse(&head, &question, &answer, (void **)&buf, &size);
		sendto(srv->sock, buf, size, 0, (struct sockaddr*)&srv->client, sizeof(srv->client));
	}
	return 0; //packet sent
}

int server(struct dnsServer *srv)
{
	int recvlen;
	int slen = sizeof(srv->client);
	//initialize the server
	if ((srv->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		return die("SOCKET", -1);
	memset(&srv->server, 0, sizeof(srv->server));
	srv->server.sin_family = AF_INET;
	srv->server.sin_port = htons(srv->port);
	srv->server.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(srv->sock, (struct sockaddr*)&srv->server, sizeof(srv->server)) == -1)
		return die("BIND", -1);
	for (;;)
	{
		if ((recvlen = recvfrom(srv->sock, srv->buffer, BUFFER_LEN,
		     0, (struct sockaddr *)&srv->client, &slen)) == -1)
		{
			close(srv->sock);
			return die("RECV", -1);
		}
		handleRequest(srv, recvlen);
	}
	close(srv->sock);
	return 0;
}

int main()
{
	struct dnsServer *srv = malloc(sizeof(struct dnsServer));
	srv->port = 53;
	return server(srv);
}
