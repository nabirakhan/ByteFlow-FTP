CC = gcc
CFLAGS = -Wall -Wextra -g -I.
LDFLAGS = -lssl -lcrypto -lpthread -lsqlite3

all: server client init_db

server: server.c common.h
	$(CC) $(CFLAGS) -o server server.c $(LDFLAGS)

client: client.c common.h
	$(CC) $(CFLAGS) -o client client.c $(LDFLAGS)

init_db: init_db.c
	$(CC) $(CFLAGS) -o init_db init_db.c -lsqlite3

cert:
	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

clean:
	rm -f server client init_db

db_clean:
	rm -f users.db

full_clean: clean db_clean

.PHONY: all clean cert init_db db_clean full_clean
