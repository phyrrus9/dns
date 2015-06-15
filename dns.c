/*
	simple DNS server that processes A requests to implement
	internal network DNS name resolution (using TLD names
	to resolve internal addresses)
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "dns.h"
#include "resolve.h"

int setDNSHeaderField(struct DNSHeader *head, enum DNSHeaderField field, uint16_t val)
{
	val = htons(val); //convert to big endian
	switch (field)
	{
		case FIELD_ID:		return head->id = val;
		case FIELD_QUESTIONS:	return head->qc = val;
		case FIELD_ANSWERS:	return head->ac = val;
		case FIELD_ADDITIONAL:	return head->dc = val;
		default:		return 0; //unknown field
	}
}

uint16_t getDNSHeaderField(struct DNSHeader *head, enum DNSHeaderField field)
{
	switch (field)
	{
		case FIELD_ID:		return htons(head->id);
		case FIELD_QUESTIONS:	return htons(head->qc);
		case FIELD_ANSWERS:	return htons(head->ac);
		case FIELD_NS:		return htons(head->nc);
		case FIELD_ADDITIONAL:	return htons(head->dc);
		default:		return 0xFFFF; //unknown field
	}
}

int setDNSHeaderOption(struct DNSHeader *head, enum DNSHeaderOption opt, uint8_t val)
{
	switch (opt)
	{
		case OPT_QR:			return head->qr = val;
		case OPT_OPCODE:		return head->op = val;
		case OPT_AUTHORITIVE_ANSWER:	return head->aa = val;
		case OPT_TRUNCATION:		return head->tc = val;
		case OPT_REQUEST_RECURSION:	return head->rd = val;
		case OPT_RECURSION_AVAILABLE:	return head->ra = val;
		case OPT_ZBIT:			return head->zf = val;
		case OPT_RCODE:			return head->rc = val;
		default: 			return 0; //unknown option
	}
}

uint8_t getDNSHeaderOption(struct DNSHeader *head, enum DNSHeaderOption opt)
{
	switch (opt)
	{
		case OPT_QR:			return head->qr;
		case OPT_OPCODE:		return head->op;
		case OPT_AUTHORITIVE_ANSWER:	return head->aa;
		case OPT_TRUNCATION:		return head->tc;
		case OPT_REQUEST_RECURSION:	return head->rd;
		case OPT_RECURSION_AVAILABLE:	return head->ra;
		case OPT_ZBIT:			return head->zf;
		case OPT_RCODE:			return head->rc;
	}
	return 0xFF; //unknown option
}

void initDNSHeader(struct DNSHeader *head) //zeroes the entire header
{ memset(head, 0, sizeof(struct DNSHeader)); }

int8_t *int8ptr_postinc(int8_t **ptr, uint32_t increment)
{
	int8_t *ret = *ptr;
	*ptr += increment;
	return ret;
}

int8_t *readDNSHeader(struct DNSHeader *head, int8_t *ptr)
{
	initDNSHeader(head);
	memcpy((void *)head, int8ptr_postinc(&ptr, sizeof(struct DNSHeader)),
	       sizeof(struct DNSHeader));
	return ptr;
}

int8_t *readDNSQuestion(struct DNSQuestion *question, int8_t *ptr)
{
	//first get the name
	int8_t *orig_ptr = ptr;
	uint8_t qname_tlen = 0;
	uint16_t qname_buf_size = 0;
	int8_t * qname_buf = NULL;
	int8_t * qname_tbuf = NULL;
	do
	{
		memcpy(&qname_tlen, int8ptr_postinc(&ptr, sizeof(uint8_t)),
			sizeof(uint8_t)); //get length of segment
		if (qname_tlen == 0)
			break; //dont even bother...
		qname_tbuf = (int8_t *)malloc(qname_tlen); //allocate a buffer for segment
		memcpy(qname_tbuf, int8ptr_postinc(&ptr, qname_tlen),
			qname_tlen); //copy segment into buffer
		if (qname_buf_size == 0) //nothing in buffer yet
		{
			qname_buf = (int8_t *)malloc(qname_tlen);
			qname_buf_size = qname_tlen;
			memcpy(qname_buf, qname_tbuf, qname_tlen);
		}
		else //insert into buffer
		{
			int8_t *tmpbuf = (int8_t *)malloc(qname_buf_size +
						qname_tlen + 1); //allocate temp buffer
			tmpbuf[qname_buf_size] = '.'; //place segment separator
			memcpy(&tmpbuf[qname_buf_size + 1], qname_tbuf, qname_tlen); //insert
			memcpy(tmpbuf, qname_buf, qname_buf_size); //copy in the old data
			free(qname_buf); //delete old data
			qname_buf = tmpbuf; //set new data
			qname_buf_size += qname_tlen + 1; //update size
		}
		free(qname_tbuf); //delete memory for old segment
	} while (qname_tlen > 0); //this may introduce a bug
	int8_t *qname_ptr = (int8_t *)malloc(qname_buf_size + 1);
	memcpy(qname_ptr, qname_buf, qname_buf_size); //copy full name
	qname_ptr[qname_buf_size] = 0; //make it a NULL-terminated string
	free(qname_buf); //remove data buffer
	question->qname = qname_ptr; //set the string in the struct
	question->original_size = ptr - orig_ptr;
	memcpy(&question->original, orig_ptr, question->original_size);
	//get type and class
	memcpy(&question->qtype, int8ptr_postinc(&ptr, sizeof(uint16_t)),
		sizeof(uint16_t)); //read the type
	memcpy(&question->qclass, int8ptr_postinc(&ptr, sizeof(uint16_t)),
		sizeof(uint16_t)); //read the class
	question->qtype = htons(question->qtype);
	question->qclass = htons(question->qclass);
	return ptr; //return pointer to end of question
}

struct DNSAnswer createDNSAnswer(struct DNSQuestion *question, char *addr)
{
	struct DNSAnswer ret;
	union { uint32_t address;  uint8_t bytes[4]; } combine;
	uint8_t tmp;
	if (addr == NULL)
		ret.rcode = 0x4; //not implemented type
	else
		ret.rcode = 0x0;
	sscanf(addr, "%d.%d.%d.%d",
		(int *)&combine.bytes[0],
		(int *)&combine.bytes[1],
		(int *)&combine.bytes[2],
		(int *)&combine.bytes[3]);
	ret.addr = combine.address;
	return ret;
}

uint8_t *createNAME(int8_t *host, uint16_t *size)
{
	uint8_t *buf = malloc(255), *ptr = buf, *ret;
	int8_t *pch = strtok(host, ".");
	while (pch != NULL)
	{
		uint8_t len = strlen(pch);
		*ptr++ = len;
		memcpy(ptr, pch, len);
		ptr += len;
		pch = strtok(NULL, ".");
	}
	*ptr = 0;
	*size = ptr - buf;
	ret = malloc(*size);
	memcpy(ret, buf, *size);
	free(buf);
	return ret;
}

void createDNSResponse(struct DNSHeader *head, struct DNSQuestion *question, struct DNSAnswer *answer,
			void **buf, uint16_t *size)
{
	bool allocated = *buf == NULL;
	if (*buf == NULL)
		*buf = malloc(0xFF); //allocate it
	struct DNSHeader resphead;
	char *ptr = (char *)*buf, *curr = ptr;
#define ANSWER_LEN 0x0B
	char answerbytes[ANSWER_LEN] =
		{ 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04 };
	uint16_t qname_size;
	uint8_t *qname;
	initDNSHeader(&resphead);
	setDNSHeaderOption(&resphead, OPT_QR, 1);
	setDNSHeaderField(&resphead, FIELD_ID,
			  getDNSHeaderField(head, FIELD_ID)); //mimic the ID
	setDNSHeaderField(&resphead, FIELD_QUESTIONS, 0);
			  //getDNSHeaderField(head, FIELD_QUESTIONS)); //mimic the Qcount
	setDNSHeaderField(&resphead, FIELD_ANSWERS, 1);
	setDNSHeaderField(&resphead, FIELD_ADDITIONAL, 0); //never have any additional sections
	memcpy(int8ptr_postinc((int8_t **)&curr, sizeof(struct DNSHeader)),
	       &resphead, sizeof(struct DNSHeader)); //copy the header in
	qname = createNAME(question->qname, &qname_size);
	memcpy(int8ptr_postinc((int8_t **)&curr, qname_size), qname, qname_size); //copy the name
	free(qname);
	memcpy(int8ptr_postinc((int8_t **)&curr, ANSWER_LEN), answerbytes, ANSWER_LEN); //copy answer header
	memcpy(int8ptr_postinc((int8_t **)&curr, 0x04), &answer->addr, 0x04); //copy addr
	*size = curr - ptr; //set the size
}

char *resolveHost(char *hostname)
{
	struct Arecord *rec = resolve(hostname);
	char *ret;
	if (rec == NULL) return NULL;
	ret = strdup(rec->addr);
	free(rec);
	return ret;
}
