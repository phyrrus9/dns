#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "resolve.h"

int main(int argc, char ** argv)
{
	FILE *fp;
	int i;
	char *hostname, *addr;
	if (!strcmp(argv[1], "write"))
	{
		fp = fopen("A.txt", "a+b");
		for (i = 2; i < argc; i++)
		{
			hostname = malloc(128);
			addr     = malloc(32);
			sscanf(argv[i], "%[^:]:%s", hostname, addr);
			Arecord_write(fp, hostname, addr);
			free(hostname);
			free(addr);
		}
		fflush(fp);
		fclose(fp);
	}
	else if (!strcmp(argv[1], "read"))
	{
		fp = fopen("A.txt", "rb");
		struct Arecord *rec;
		while ((rec = Arecord_read(fp)) != NULL)
		{
			printf("%s\t%s\n", rec->hostname, rec->addr);
			free(rec);
		}
		fclose(fp);
	}
	else if (!strcmp(argv[1], "resolve"))
	{
		struct Arecord *rec;
		for (i = 2; i < argc; i++)
		{
			rec = resolve(argv[i]);
			if (rec == NULL)
				printf("%s\tUNKNOWN\n", argv[i]);
			else
			{
				printf("%s\t%s\n", rec->hostname, rec->addr);
				free(rec);
			}
		}
	}
	return 0;
}
