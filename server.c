#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>
#include "dns.h"

#define BUFFER_LEN 512

#define DEBUG 0

#define TYPE_A 		0x0001
#define TYPE_NS		0x0002
#define TYPE_CNAME	0x0005
#define TYPE_SOA	0x0006
#define TYPE_WKS	0x000B
#define TYPE_PTR	0x000C
#define TYPE_MX		0x000F
#define TYPE_SRV	0x0021
#define TYPE_A6		0x0026

#define CLASS_IN	0x0001

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

int passthrough(struct dnsServer *srv, int len)
{
	int sockfd, recvlen;
	struct sockaddr_in serv;
	memset(&serv, 0, sizeof(serv));
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr=inet_addr("8.8.8.8");
	serv.sin_port=htons(53);
	sendto(	sockfd, srv->buffer, len, 0,
		(struct sockaddr *)&serv, sizeof(serv));
	recvlen = recvfrom(sockfd, srv->buffer, BUFFER_LEN, 0, NULL, NULL);
	close(sockfd);
	sendto(	srv->sock, srv->buffer, recvlen, 0,
		(struct sockaddr *)&srv->client, sizeof(srv->client));
#if DEBUG == 1
	printf("Packet passthrough success\n");
#endif
	return 0;
}

int handleRequest(struct dnsServer *srv, int len)
{
	struct DNSHeader head;
	struct DNSQuestion question;
	struct DNSAnswer answer;
	int8_t *ptr = srv->buffer;
	char *addr, *buf = NULL;
	uint16_t size;
	uint8_t found = 0;
	ptr = readDNSHeader(&head, ptr);
	ptr = readDNSQuestion(&question, ptr);
	if (question.qtype == TYPE_A)
		addr = resolveHost(question.qname);
	else if (question.qtype = TYPE_PTR)
		addr = resolveAddress(question.qname);
#if DEBUG == 1
		printf("Received packet from %s:%d\tID: %04x\n",
			inet_ntoa(srv->client.sin_addr), ntohs(srv->client.sin_port), head.id);
		printf("NAME TO RESOLVE: %s\t%s\n", question.qname, addr);
#endif
	if ((question.qtype != TYPE_A && question.qtype != TYPE_PTR || question.qclass != CLASS_IN) ||
	    addr == NULL)
	{
		passthrough(srv, len);
	}
	else
	{
		answer = createDNSAnswer(&question, addr, question.qtype == TYPE_A);
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
