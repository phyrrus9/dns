all: dns db
clean:
	rm -rf dns db_util A.txt
dns: server.c dns.c resolve.c dns.h resolve.h
	gcc -o dns server.c dns.c resolve.c
db: db_util.c resolve.c resolve.h
	gcc -o db_util db_util.c resolve.c
