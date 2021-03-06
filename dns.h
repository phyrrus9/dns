/*
	simple DNS server that processes A requests to implement
	internal network DNS name resolution (using TLD names
	to resolve internal addresses)
*/

#ifndef DNS_DNS_H
#define DNS_DNS_H

#include <stdint.h>
enum DNSHeaderOption {
		OPT_QR  		=	0x001,
		OPT_OPCODE 		=	0x002,
		OPT_AUTHORITIVE_ANSWER 	=	0x004,
		OPT_TRUNCATION		=	0x008,
		OPT_REQUEST_RECURSION	=	0x010,
		OPT_RECURSION_AVAILABLE	=	0x020,
		OPT_ZBIT 		=	0x040,
		OPT_RCODE		=	0x080,
		OPT_AUTHENTICATED	=	0x100};
enum DNSHeaderField {
		FIELD_ID		=	0x01,
		FIELD_QUESTIONS		=	0x02,
		FIELD_ANSWERS		=	0x04,
		FIELD_NS		=	0x08,
		FIELD_ADDITIONAL	=	0x10};
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
	uint16_t nc; //NS count
	uint16_t dc; //additional count, should always use 0
};
struct DNSQuestion
{
	int8_t *qname;
	uint16_t qtype;
	uint16_t qclass;
};
struct DNSAnswer
{
	uint8_t isaddr; //1 if addr, 0 if name
	uint8_t rcode :4;
	uint32_t addr;
	uint8_t *name;
	uint16_t namesize;
};
int setDNSHeaderField(struct DNSHeader *head, enum DNSHeaderField field, uint16_t val);
uint16_t getDNSHeaderField(struct DNSHeader *head, enum DNSHeaderField field);
int setDNSHeaderOption(struct DNSHeader *head, enum DNSHeaderOption opt, uint8_t val);
uint8_t getDNSHeaderOption(struct DNSHeader *head, enum DNSHeaderOption opt);
void initDNSHeader(struct DNSHeader *head);
int8_t *int8ptr_postinc(int8_t **ptr, uint32_t increment);
int8_t *readDNSHeader(struct DNSHeader *head, int8_t *ptr);
int8_t *readDNSQuestion(struct DNSQuestion *question, int8_t *ptr);
struct DNSAnswer createDNSAnswer(struct DNSQuestion *question, char *addr, uint8_t isaddr);
void createDNSResponse(struct DNSHeader *head, struct DNSQuestion *question, struct DNSAnswer *answer,
			void **buf, uint16_t *size);
uint8_t *createNAME(int8_t *addr, uint16_t *size);
char *resolveHost(char *hostname);
char *resolveAddress(char *addr);

#endif
