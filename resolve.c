#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "resolve.h"

struct Arecord *Arecord_read(FILE *fp)
{
	struct diskArecord ondisk;
	struct Arecord *ret = malloc(sizeof(struct Arecord));
	if (!fread(&ondisk, sizeof(struct diskArecord), 1, fp)) return NULL;
	ret->hostname = malloc(ondisk.hostname + 1);
	ret->addr = malloc(16);
	fread(ret->hostname, ondisk.hostname, 1, fp);
	ret->hostname[ondisk.hostname] = 0; //terminate string
	sprintf(ret->addr, "%d.%d.%d.%d",
		ondisk.addr[0],
		ondisk.addr[1],
		ondisk.addr[2],
		ondisk.addr[3]);
	return ret;
}

void Arecord_free(struct Arecord *record)
{
	free(record->hostname);
	free(record->addr);
	free(record);
}

void Arecord_write(FILE *fp, char *hostname, char *addr)
{
	struct diskArecord ondisk;
	ondisk.hostname = strlen(hostname);
	sscanf(addr, "%d.%d.%d.%d",
		(int *)&ondisk.addr[0],
		(int *)&ondisk.addr[1],
		(int *)&ondisk.addr[2],
		(int *)&ondisk.addr[3]);
	fwrite(&ondisk, sizeof(struct diskArecord), 1, fp);
	fwrite(hostname, ondisk.hostname, 1, fp);
}

void Arecord_remove(FILE *fp, char *hostname)
{
	char *tmpfname = tempnam(NULL, "A_DB_");
	FILE *tmpf = fopen(tmpfname, "wb");
	char buf[256];
	struct diskArecord rec;
	long int oldpos = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	while (fread(&rec, sizeof(struct diskArecord), 1, fp))
	{
		fread(buf, rec.hostname, 1, fp);
		buf[rec.hostname] = 0; //null terminate it
		if (strcmp(buf, hostname))
		{
			fwrite(&rec, sizeof(struct diskArecord), 1, tmpf);
			fwrite(buf, rec.hostname, 1, tmpf);
		}
	}
	fflush(tmpf);
	freopen(NULL, "rb", tmpf);
	freopen(NULL, "wb", fp);
	while (fread(buf, 1, 1, tmpf)) fwrite(buf, 1, 1, fp);
	fflush(fp);
	fclose(tmpf);
	unlink(tmpfname);
	freopen(NULL, "rb", fp);
	fseek(fp, oldpos, SEEK_SET);
}

struct Arecord *resolve(char *hostname)
{
	struct Arecord *ret = NULL;
	FILE *fp;
	if ((fp = fopen("A.txt", "rb")) == NULL)
		return NULL;
	while ((ret = Arecord_read(fp)) != NULL)
	{
		if (strcmp(hostname, ret->hostname) == 0)
		{
			fclose(fp);
			return ret;
		}
		free(ret);
	}
	fclose(fp);
	return NULL;
}
