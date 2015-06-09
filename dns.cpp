/*
	simple DNS server that processes A requests to implement
	internal network DNS name resolution (using TLD names
	to resolve internal addresses)
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "mysql-cpp/mySQLCon.h"
#include "mysql-cpp/mySQLResult.h"
extern "C" {
enum DNSHeaderOption {
		OPT_QR  		=	0x01,
		OPT_OPCODE 		=	0x02,
		OPT_AUTHORITIVE_ANSWER 	=	0x04,
		OPT_TRUNCATION		=	0x08,
		OPT_REQUEST_RECURSION	=	0x10,
		OPT_RECURSION_AVAILABLE	=	0x20,
		OPT_ZBIT 		=	0x40,
		OPT_RCODE		=	0x80 };
enum DNSHeaderField {
		FIELD_ID		=	0x01,
		FIELD_QUESTIONS		=	0x02,
		FIELD_ANSWERS		=	0x04,
		FIELD_ADDITIONAL	=	0x08};
struct DNSHeader
{
	uint16_t id;
	uint8_t rd		:1; //request recursion
	uint8_t tc		:1; //truncated
	uint8_t aa		:1; //authoritive answer
	uint8_t op		:4; //opcode
	uint8_t qr		:1; //QUERY=1,RESPONSE=0
	uint8_t rc		:4; //response code
	uint8_t cd		:1; //checking disabled
	uint8_t ad		:1; //authenticated data
	uint8_t zf		:1; //Z-flag (unused)
	uint8_t ra		:1; //recursion available
	uint16_t qc; //question count
	uint16_t ac; //answer count
	uint16_t dc; //additional count, should always use 0
};
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
		case FIELD_ID:		return ntohs(head->id);
		case FIELD_QUESTIONS:	return ntohs(head->qc);
		case FIELD_ANSWERS:	return ntohs(head->ac);
		case FIELD_ADDITIONAL:	return ntohs(head->dc);
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
struct DNSQuestion
{
	int8_t *qname;
	uint16_t qtype;
	uint16_t qclass;
	uint8_t *original;
	uint16_t original_size;
};
int8_t *int8ptr_postinc(int8_t **ptr, uint32_t increment)
{
	int8_t *ret = *ptr;
	*ptr += increment;
	return ret;
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
	memcpy(&question->qclass, int8ptr_postinc(&ptr, sizeof(uint16_t)),
		sizeof(uint16_t)); //read the class
	memcpy(&question->qtype, int8ptr_postinc(&ptr, sizeof(uint16_t)),
		sizeof(uint16_t)); //read the type
	return ptr; //return pointer to end of question
}
struct DNSAnswer
{
	uint8_t rcode :4;
	uint32_t addr;
};
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
void createDNSResponse(struct DNSHeader *head, struct DNSQuestion *question, struct DNSAnswer *answer,
			void **buf, uint16_t *size)
{
	bool allocated = *buf == NULL;
	if (*buf == NULL)
		*buf = malloc(0xFF); //allocate it
	struct DNSHeader resphead;
	char *ptr = (char *)*buf, *curr = ptr;
	char answerbytes[0x0C] =
		{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04};
	initDNSHeader(&resphead);
	setDNSHeaderField(&resphead, FIELD_ID,
			  getDNSHeaderField(head, FIELD_ID)); //mimic the ID
	setDNSHeaderField(&resphead, FIELD_QUESTIONS,
			  getDNSHeaderField(head, FIELD_QUESTIONS)); //mimic the Qcount
	setDNSHeaderField(&resphead, FIELD_ANSWERS, answer->rcode == 0 ? 0 : 1);
	setDNSHeaderField(&resphead, FIELD_ADDITIONAL, 0); //never have any additional sections
	memcpy(int8ptr_postinc((int8_t **)&curr, sizeof(struct DNSHeader)),
	       &resphead, sizeof(struct DNSHeader)); //copy the header in
	memcpy(int8ptr_postinc((int8_t **)&curr, question->original_size),
	       question->original, question->original_size); //copy original in
	memcpy(int8ptr_postinc((int8_t **)&curr, 0x0C), answerbytes, 0x0C); //copy answer header
	memcpy(int8ptr_postinc((int8_t **)&curr, 0x04), &answer->addr, 0x04); //copy addr
	*size = curr - ptr; //set the size
}
}
char *resolve(char *hostname)
{

}
int main() {}
