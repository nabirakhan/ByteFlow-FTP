all: myftpserver myftpclient
CC = gcc

myftpserver: myftpserver.c myftp.h
	$(CC) myftpserver.c -o myftpserver -lpthread


myftpclient: myftpclient.c myftp.h
	$(CC) myftpclient.c -o myftpclient

 




