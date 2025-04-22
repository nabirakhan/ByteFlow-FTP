CC = gcc
CFLAGS = -Wall -Wextra -g -I.
LDFLAGS = -lssl -lcrypto -lpthread

all: server client

server: server.c common.h
	$(CC) $(CFLAGS) -o server server.c $(LDFLAGS)

client: client.c common.h
	$(CC) $(CFLAGS) -o client client.c $(LDFLAGS)

cert:
	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

clean:
	rm -f server client

.PHONY: all clean cert