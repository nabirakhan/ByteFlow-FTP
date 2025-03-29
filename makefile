CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto -lpthread

all: myftpserver myftpclient

myftpserver: myftpserver.c myftp.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

myftpclient: myftpclient.c myftp.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f myftpserver myftpclient
