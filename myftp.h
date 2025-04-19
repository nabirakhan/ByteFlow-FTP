#ifndef MYFTP_H
#define MYFTP_H

#include<stdio.h>
#include<string.h>
#include<sys/socket.h> 
#include<arpa/inet.h> //inet_addr
#include<unistd.h>
#include<stdlib.h>
#include<dirent.h>
#include<errno.h>
#include<pthread.h>
#include<semaphore.h>

// Protocol definitions
#define PROTOCOL_HEADER 0xe3
#define MAX_PAYLOAD_SIZE 1024

// Message types
#define OPEN_CONN_REQUEST  0xA1
#define OPEN_CONN_REPLY    0xA2
#define AUTH_REQUEST       0xA3
#define AUTH_REPLY         0xA4
#define LIST_REQUEST       0xA5
#define LIST_REPLY         0xA6
#define GET_REQUEST        0xA7
#define GET_REPLY          0xA8
#define PUT_REQUEST        0xA9
#define PUT_REPLY          0xAA
#define QUIT_REQUEST       0xAB
#define QUIT_REPLY         0xAC
#define DATA_MSG           0xFF

// Message structure
struct message_s {
    char protocol[6];      // Protocol identifier (0xe3 + "myftp")
    unsigned char type;    // Message type (changed from char to unsigned char)
    char status;           // Status (1 = success, 0 = failure)
    int length;            // Total message length
    char payload[MAX_PAYLOAD_SIZE];  // Message payload
} __attribute__ ((packed));

#endif // MYFTP_H
