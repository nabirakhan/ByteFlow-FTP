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
#include <sqlite3.h>  // Added for database support

#define MAX_CLIENT_SUPPORTED     32
#define SERVER_PORT             2000
#define BUFFER_SIZE             1024
#define MAX_PATH_LENGTH         256
#define MAX_USERS               10
#define THREAD_POOL_SIZE        8
#define MAX_CACHE_ENTRIES       5
#define MAX_USERNAME_LENGTH     50
#define MAX_PASSWORD_LENGTH     50
// Add these to common.h
#define MAX_WORKERS 4
#define SHM_KEY 0x1234
#define SEM_KEY 0x5678

typedef struct {
    int worker_pids[MAX_WORKERS];
    int worker_pipes[MAX_WORKERS][2]; // [0] for read, [1] for write
    int active_connections;
    pthread_mutex_t shm_mutex;
} shared_data_t;

// Shared memory for IPC
typedef struct {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    int auth_result;
    char home_dir[MAX_PATH_LENGTH];
    sem_t sem;
} auth_shared_t;

typedef struct file_transfer {
    char filename[MAX_PATH_LENGTH];
    long filesize;
    int operation;  // 0 = download, 1 = upload
} file_transfer_t;

typedef struct command {
    int type;  // 0 = list, 1 = download, 2 = upload, 3 = cd, 4 = pwd, 5 = mkdir, 6 = rmdir, 7 = adduser, 8 = deluser, 9 = listusers
    char path[MAX_PATH_LENGTH];
    char current_dir[MAX_PATH_LENGTH];
    char username[50];      // For admin commands
    char password[50];      // For admin commands
    char home_dir[MAX_PATH_LENGTH]; // For admin commands
} command_t;

typedef struct server_state {
    sqlite3 *db;
} server_state_t;

// Function declarations
int init_database(server_state_t *state);
int authenticate_in_process(server_state_t *state, const char *username, const char *password, char *home_dir);
int add_user(server_state_t *state, const char *username, const char *password, const char *home_dir);
SSL_CTX *create_ssl_context();
void load_certificates(SSL_CTX *ctx, const char *cert_file, const char *key_file);
void *handle_client(void *arg);

#endif
