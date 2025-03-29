#ifndef MYFTP_H
#define MYFTP_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h> 
#include <arpa/inet.h> //inet_addr
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sched.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

// Protocol definitions
#define MYFTP_PROTOCOL_MAGIC 0xe3
#define MYFTP_PROTOCOL_NAME "myftp"

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
#define FILE_DATA          0xFF

// File permissions
#define READ_PERMISSION    0x4
#define WRITE_PERMISSION   0x2
#define EXECUTE_PERMISSION 0x1

// Cache configuration
#define CACHE_SIZE 10
#define MAX_FILENAME_LEN 256
#define MAX_CONTENT_SIZE 8192

// Named pipe for logging
#define LOG_FIFO "/tmp/myftp_log"

// Permission levels
#define PERM_NONE 0
#define PERM_READ 1
#define PERM_WRITE 2
#define PERM_FULL 3

// Message structure
struct message_s {
    char protocol[6];     // Protocol identifier
    char type;            // Message type (1 byte)
    char status;          // Status (1 byte)
    int length;           // Length (header + payload) (4 bytes)
    char payload[1024];   // Payload
} __attribute__ ((packed));

// File cache entry structure
typedef struct {
    char filename[MAX_FILENAME_LEN];
    unsigned char content[MAX_CONTENT_SIZE];
    size_t size;
    time_t last_accessed;
    int permissions;      // Bit flags for permissions
    int is_valid;         // Whether this entry contains valid data
} cache_entry_t;

// Client session structure
typedef struct {
    int socket;
    char username[64];
    int permission_level;
    unsigned char session_key[32];  // AES-256 encryption key
    int is_authenticated;
} client_session_t;

// Function prototypes
int check_file_permissions(const char *filepath, int required_permissions);
void set_file_permissions(const char *filepath, int permissions);
void log_message(const char *message);
int encrypt_data(unsigned char *plaintext, int plaintext_len, 
                unsigned char *key, unsigned char *iv, 
                unsigned char *ciphertext);
int decrypt_data(unsigned char *ciphertext, int ciphertext_len, 
                unsigned char *key, unsigned char *iv, 
                unsigned char *plaintext);
void set_process_priority(int priority);
void *get_cached_file(const char *filename);
void cache_file(const char *filename, void *content, size_t size, int permissions);
void init_file_cache();
void cleanup_file_cache();

#endif /* MYFTP_H */
