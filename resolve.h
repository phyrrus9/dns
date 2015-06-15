#include <stdio.h>

#ifndef DNS_RESOLVE_H
#define DNS_RESOLVE_H

enum Aresolve_type_enum { A_BYHOST, A_BYADDR };
typedef enum Aresolve_type_enum AType;

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
void Arecord_remove(FILE *fp, char *hostname);
struct Arecord *resolve(char *opt, AType by);

#endif
