#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <semaphore.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_CLIENT_SUPPORTED     32
#define SERVER_PORT             2000
#define BUFFER_SIZE             1024
#define MAX_PATH_LENGTH         256
#define MAX_USERS               10
#define THREAD_POOL_SIZE        8
#define MAX_CACHE_ENTRIES       5

typedef struct auth_struct {
    char username[50];
    char password[50];
} auth_struct_t;

typedef struct file_transfer {
    char filename[MAX_PATH_LENGTH];
    long filesize;
    int operation;  // 0 = download, 1 = upload
} file_transfer_t;

typedef struct command {
    int type;  // 0 = list, 1 = download, 2 = upload, 3 = delete, 4 = mkdir
    char path[MAX_PATH_LENGTH];
} command_t;

typedef struct user {
    char username[50];
    char password[50];
    char home_dir[MAX_PATH_LENGTH];
} user_t;

// Global variables
extern user_t users[MAX_USERS];
extern int user_count;

// Function declarations
void initialize_users();
int authenticate_user(char *username, char *password);
SSL_CTX *create_ssl_context();
void load_certificates(SSL_CTX *ctx, const char *cert_file, const char *key_file);
void *handle_client(void *arg);

#endif