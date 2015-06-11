#include <stdio.h>

#ifndef DNS_RESOLVE_H
#define DNS_RESOLVE_H

struct diskArecord
{
	uint8_t hostname; //size
	uint8_t addr[4]; //byte-order address
};
struct Arecord
{
	char *hostname;
	char *addr;
};
struct Arecord *Arecord_read(FILE *fp);
void Arecord_free(struct Arecord *record);
void Arecord_write(FILE *fp, char *hostname, char *addr);
struct Arecord *resolve(char *hostname);

#endif
