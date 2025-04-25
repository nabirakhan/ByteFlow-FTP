#include "common.h"
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sqlite3.h>
#include <semaphore.h>
#include <signal.h>

// Global variables for thread pool and synchronization
pthread_t thread_pool[THREAD_POOL_SIZE];          // Pool of worker threads
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER; // Mutex for thread safety
pthread_cond_t cond_var = PTHREAD_COND_INITIALIZER; // Condition variable for thread signaling
pthread_rwlock_t download_lock = PTHREAD_RWLOCK_INITIALIZER;  // RWLock for download operations
sem_t upload_sem;                                 // Semaphore for upload operations (binary)
int shutdown_server = 0;                          // Flag for graceful shutdown

// Structure to hold client connection information
typedef struct {
    int client_fd;                // Client socket file descriptor
    SSL *ssl;                     // SSL connection object
    server_state_t *state;        // Pointer to server state
    char username[MAX_USERNAME_LENGTH]; // Authenticated username
    char password[MAX_PASSWORD_LENGTH]; // Authenticated password
    char home_dir[MAX_PATH_LENGTH];     // Client's home directory
} client_info_t;

// Structure for authentication results (used in IPC)
typedef struct {
    int authenticated;            // Authentication status (1=success, 0=failure)
    char username[MAX_USERNAME_LENGTH]; // Username
    char password[MAX_PASSWORD_LENGTH]; // Password
    char home_dir[MAX_PATH_LENGTH];     // Home directory path
} auth_result_t;

// Circular queue for client connections
client_info_t client_queue[MAX_CLIENT_SUPPORTED];
int queue_front = 0;              // Front of queue index
int queue_rear = -1;              // Rear of queue index
int queue_count = 0;              // Current queue size

// Signal handler for graceful shutdown
void handle_shutdown(int sig) {
    (void)sig;
    printf("\nShutting down server...\n");
    // Clean up synchronization primitives
    pthread_rwlock_destroy(&download_lock);
    sem_destroy(&upload_sem);
    exit(EXIT_SUCCESS);
}

// Initialize SQLite database for user management
int init_database(server_state_t *state) {
    int rc = sqlite3_open("users.db", &state->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(state->db));
        sqlite3_close(state->db);
        return 0;
    }

    // Create users table with username, password and home directory columns
    const char *sql = "CREATE TABLE IF NOT EXISTS users ("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "username TEXT UNIQUE NOT NULL,"
                      "password TEXT NOT NULL,"
                      "home_dir TEXT NOT NULL);";
    
    char *err_msg = 0;
    rc = sqlite3_exec(state->db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(state->db);
        return 0;
    }

    // Add default admin user if not exists
    sql = "INSERT OR IGNORE INTO users (username, password, home_dir) "
          "VALUES ('admin', 'password', '/mnt/e/linux/ftpp');";
    rc = sqlite3_exec(state->db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    }

    return 1;
}

// Add a new user to the database
int add_user(server_state_t *state, const char *username, const char *password, const char *home_dir) {
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO users (username, password, home_dir) VALUES (?, ?, ?)";
    
    if (sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(state->db));
        return 0;
    }
    
    // Bind parameters to prevent SQL injection
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, home_dir, -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to add user: %s\n", sqlite3_errmsg(state->db));
        return 0;
    }
    
    return 1;
}

// Delete a user from the database
int delete_user(server_state_t *state, const char *username) {
    sqlite3_stmt *stmt;
    const char *sql = "DELETE FROM users WHERE username = ?";
    
    if (sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(state->db));
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to delete user: %s\n", sqlite3_errmsg(state->db));
        return 0;
    }
    
    return 1;
}

// List all users in the database (admin only)
int list_users(server_state_t *state, SSL *ssl) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT username, home_dir FROM users ORDER BY username";
    
    if (sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(state->db));
        SSL_write(ssl, "LIST_USERS_FAILED", 17);
        return 0;
    }

    // Send header to client
    SSL_write(ssl, "USER_LIST_START", 15);
    
    // Send each user's info to client
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        char user_info[512];
        const char *username = (const char *)sqlite3_column_text(stmt, 0);
        const char *home_dir = (const char *)sqlite3_column_text(stmt, 1);
        
        snprintf(user_info, sizeof(user_info), "%-20s %s", username, home_dir);
        SSL_write(ssl, user_info, strlen(user_info));
    }

    SSL_write(ssl, "USER_LIST_END", 13);
    sqlite3_finalize(stmt);
    return 1;
}

// Authenticate user in a separate process for security
int authenticate_in_process(server_state_t *state, const char *username, const char *password, char *home_dir) {
    // Create shared memory for inter-process communication
    int shm_fd = shm_open("/ftp_auth_shm", O_CREAT | O_RDWR, 0666);
    ftruncate(shm_fd, sizeof(auth_shared_t));
    auth_shared_t *shared = mmap(NULL, sizeof(auth_shared_t), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    
    sem_init(&shared->sem, 1, 0); // Initialize semaphore
    
    // Copy credentials to shared memory
    strncpy(shared->username, username, MAX_USERNAME_LENGTH);
    strncpy(shared->password, password, MAX_PASSWORD_LENGTH);
    
    pid_t pid = fork();
    if (pid == 0) { // Child process
        // Perform authentication query
        sqlite3_stmt *stmt;
        const char *sql = "SELECT password, home_dir FROM users WHERE username = ?";
        
        if (sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            shared->auth_result = 0;
            sem_post(&shared->sem);
            exit(1);
        }
        
        sqlite3_bind_text(stmt, 1, shared->username, -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *stored_pass = (const char *)sqlite3_column_text(stmt, 0);
            const char *db_home_dir = (const char *)sqlite3_column_text(stmt, 1);
            
            strncpy(shared->home_dir, db_home_dir, MAX_PATH_LENGTH);
            shared->auth_result = (strcmp(shared->password, stored_pass) == 0);
        } else {
            shared->auth_result = 0;
        }
        
        sqlite3_finalize(stmt);
        sem_post(&shared->sem); // Signal completion
        sqlite3_close(state->db);
        exit(0);
    }
    else if (pid > 0) { // Parent process
        sem_wait(&shared->sem); // Wait for child to complete
        
        int result = shared->auth_result;
        if (result) {
            strncpy(home_dir, shared->home_dir, MAX_PATH_LENGTH);
        }
        
        // Cleanup shared memory
        sem_destroy(&shared->sem);
        munmap(shared, sizeof(auth_shared_t));
        close(shm_fd);
        shm_unlink("/ftp_auth_shm");
        
        // Wait for child to prevent zombies
        waitpid(pid, NULL, 0);
        return result;
    }
    else {
        perror("fork failed");
        return 0;
    }
}

// Create SSL context for secure connections
SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx;
    const SSL_METHOD *method;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Load SSL certificates
void load_certificates(SSL_CTX *ctx, const char *cert_file, const char *key_file) {
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// Add client to the work queue
void enqueue_client(client_info_t client) {
    pthread_mutex_lock(&mutex);
    if (queue_count < MAX_CLIENT_SUPPORTED) {
        queue_rear = (queue_rear + 1) % MAX_CLIENT_SUPPORTED;
        client_queue[queue_rear] = client;
        queue_count++;
        pthread_cond_signal(&cond_var); // Signal worker threads
    }
    pthread_mutex_unlock(&mutex);
}

// Get next client from the work queue
client_info_t dequeue_client() {
    pthread_mutex_lock(&mutex);
    while (queue_count == 0 && !shutdown_server) {
        pthread_cond_wait(&cond_var, &mutex); // Wait for clients
    }
    
    client_info_t client = { -1, NULL, NULL, "", "", ""};
    if (!shutdown_server) {
        client = client_queue[queue_front];
        queue_front = (queue_front + 1) % MAX_CLIENT_SUPPORTED;
        queue_count--;
    }
    pthread_mutex_unlock(&mutex);
    return client;
}

// Worker thread function
void *thread_function(void *arg) {
    (void)arg;
    while (!shutdown_server) {
        client_info_t client = dequeue_client();
        if (client.client_fd != -1) {
            handle_client((void *)&client);
        }
    }
    return NULL;
}

// Handle client connection and commands
void *handle_client(void *arg) {
    client_info_t *client = (client_info_t *)arg;
    int client_fd = client->client_fd;
    SSL *ssl = client->ssl;
    server_state_t *state = client->state;

    auth_shared_t auth_data;

    // Receive authentication data from client
    int bytes = SSL_read(ssl, &auth_data, sizeof(auth_shared_t));
    if (bytes <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    char home_dir[MAX_PATH_LENGTH];
    if (!authenticate_in_process(state, auth_data.username, auth_data.password, home_dir)) {
        SSL_write(ssl, "AUTH_FAIL", 9);
        goto cleanup;
    }

    SSL_write(ssl, "AUTH_SUCCESS", 12);
    char current_dir[MAX_PATH_LENGTH];
    strncpy(current_dir, home_dir, MAX_PATH_LENGTH);

    // Main command processing loop
    command_t cmd;
    while (1) {
        bytes = SSL_read(ssl, &cmd, sizeof(command_t));
        if (bytes <= 0) break;
        
        switch (cmd.type) {
            case 0: {  // LIST - List directory contents
                DIR *dir;
                struct dirent *ent;
                char full_path[MAX_PATH_LENGTH];
                strncpy(full_path, current_dir, sizeof(full_path));
                strncat(full_path, "/", sizeof(full_path));
                strncat(full_path, cmd.path, sizeof(full_path));
                
                if ((dir = opendir(full_path)) != NULL) {
                    while ((ent = readdir(dir)) != NULL) {
                        SSL_write(ssl, ent->d_name, strlen(ent->d_name));
                        SSL_write(ssl, "\n", 1);
                    }
                    closedir(dir);
                }
                SSL_write(ssl, "END_LIST", 8);
                break;
            }
            case 1: {  // DOWNLOAD - Send file to client
                file_transfer_t ft;
                strncpy(ft.filename, cmd.path, MAX_PATH_LENGTH);
                
                // Acquire read lock (allows concurrent downloads)
                pthread_rwlock_rdlock(&download_lock);

                char full_path[MAX_PATH_LENGTH];
                strncpy(full_path, current_dir, sizeof(full_path));
                strncat(full_path, "/", sizeof(full_path));
                strncat(full_path, cmd.path, sizeof(full_path));
                
                FILE *file = fopen(full_path, "rb");
                if (!file) {
                    ft.filesize = -1;
                    SSL_write(ssl, &ft, sizeof(file_transfer_t));
                    pthread_rwlock_unlock(&download_lock);
                    break;
                }
                
                // Get file size
                fseek(file, 0, SEEK_END);
                ft.filesize = ftell(file);
                rewind(file);
                
                SSL_write(ssl, &ft, sizeof(file_transfer_t));
                
                // Send file in chunks
                char buffer[BUFFER_SIZE];
                size_t bytes_read;
                while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
                    SSL_write(ssl, buffer, bytes_read);
                }
                
                fclose(file);
                pthread_rwlock_unlock(&download_lock);  // Release read lock
                break;
            }
            case 2: {  // UPLOAD - Receive file from client
                file_transfer_t ft;
                SSL_read(ssl, &ft, sizeof(file_transfer_t));
                
                // Try to acquire semaphore (non-blocking)
                if (sem_trywait(&upload_sem) != 0) {
                    SSL_write(ssl, "SERVER_BUSY", 11);  // Notify client
                    return NULL;
                }
                
                // Block new downloads during upload (write lock)
                pthread_rwlock_wrlock(&download_lock);
                
                char full_path[MAX_PATH_LENGTH];
                strncpy(full_path, current_dir, sizeof(full_path));
                strncat(full_path, "/", sizeof(full_path));
                strncat(full_path, cmd.path, sizeof(full_path));
                
                FILE *file = fopen(full_path, "wb");
                if (!file) {
                    SSL_write(ssl, "UPLOAD_FAIL", 11);
                    pthread_rwlock_unlock(&download_lock);
                    sem_post(&upload_sem);  // Release semaphore
                    break;
                }
                
                SSL_write(ssl, "UPLOAD_START", 12);
                
                // Receive file in chunks
                char buffer[BUFFER_SIZE];
                long remaining = ft.filesize;
                while (remaining > 0) {
                    int to_read = remaining > BUFFER_SIZE ? BUFFER_SIZE : remaining;
                    bytes = SSL_read(ssl, buffer, to_read);
                    if (bytes <= 0) break;
                    fwrite(buffer, 1, bytes, file);
                    remaining -= bytes;
                }
                
                fclose(file);
                SSL_write(ssl, "UPLOAD_COMPLETE", 15);
                pthread_rwlock_unlock(&download_lock);  // Allow downloads again
                sem_post(&upload_sem);                 // Release semaphore
                break;
            }
            case 3: {  // CD - Change directory
                char full_path[MAX_PATH_LENGTH * 2]; // For safety

                // Handle relative paths
                if (cmd.path[0] == '/') {
                    // Absolute path
                    strncpy(full_path, cmd.path, sizeof(full_path));
                } else {
                    // Relative path
                    strncpy(full_path, current_dir, sizeof(full_path));
                    strncat(full_path, "/", sizeof(full_path));
                    strncat(full_path, cmd.path, sizeof(full_path));
                }

                // Normalize path (remove ./ and ../)
                char *resolved_path = realpath(full_path, NULL);
                if (!resolved_path) {
                    SSL_write(ssl, "CD_FAILED: Invalid path", 22);
                    break;
                }

                // Security check: ensure new path is within home directory
                if (strncmp(resolved_path, home_dir, strlen(home_dir)) != 0) {
                    SSL_write(ssl, "CD_FAILED: Access denied", 24);
                    free(resolved_path);
                    break;
                }

                // Verify it's a directory
                struct stat statbuf;
                if (stat(resolved_path, &statbuf) == -1 || !S_ISDIR(statbuf.st_mode)) {
                    SSL_write(ssl, "CD_FAILED: Not a directory", 26);
                    free(resolved_path);
                    break;
                }

                // Update current directory
                strncpy(current_dir, resolved_path, MAX_PATH_LENGTH);
                free(resolved_path);
                SSL_write(ssl, "CD_SUCCESS", 10);
                break;
            }
            case 4: {  // PWD - Print working directory
                // Send back the current directory relative to home
                const char *relative_path = current_dir + strlen(home_dir);
                if (*relative_path == '\0') {
                    relative_path = "/\n(You are in your home directory)";
                }
                SSL_write(ssl, relative_path, strlen(relative_path));
                break;
            }
            case 5: { // MKDIR - Make directory
                char full_path[MAX_PATH_LENGTH];
                strncpy(full_path, current_dir, sizeof(full_path));
                strncat(full_path, "/", sizeof(full_path));
                strncat(full_path, cmd.path, sizeof(full_path));

                int status = mkdir(full_path, 0755);
                const char *msg = (status == 0) ? "Directory created successfully" : strerror(errno);
                SSL_write(ssl, msg, strlen(msg));
                break;
            }
            case 6: { // RMDIR - Remove directory
                char full_path[MAX_PATH_LENGTH];
                strncpy(full_path, current_dir, sizeof(full_path));
                strncat(full_path, "/", sizeof(full_path));
                strncat(full_path, cmd.path, sizeof(full_path));
            
                int status = rmdir(full_path);
                const char *msg = (status == 0) ? "Directory removed successfully" : strerror(errno);
                SSL_write(ssl, msg, strlen(msg));
                break;
            }
            case 7: {  // ADD_USER - Add user (admin command)
                if (strcmp(auth_data.username, "admin") != 0) {
                    SSL_write(ssl, "PERMISSION_DENIED", 17);
                    break;
                }
                
                if (add_user(state, cmd.username, cmd.password, cmd.home_dir)) {
                    SSL_write(ssl, "USER_ADDED", 11);
                } else {
                    SSL_write(ssl, "ADD_USER_FAILED", 16);
                }
                break;
            }
            case 8: {  // DEL_USER - Delete user (admin command)
                if (strcmp(auth_data.username, "admin") != 0) {
                    SSL_write(ssl, "PERMISSION_DENIED", 17);
                    break;
                }
                
                if (delete_user(state, cmd.username)) {
                    SSL_write(ssl, "USER_DELETED", 12);
                } else {
                    SSL_write(ssl, "DEL_USER_FAILED", 15);
                }
                break;
            }
            case 9: {  // LIST_USERS - List all users (admin command)
                if (strcmp(auth_data.username, "admin") != 0) {
                    SSL_write(ssl, "PERMISSION_DENIED", 17);
                    break;
                }
                
                list_users(state, ssl);
                break;
            }
            default:
                SSL_write(ssl, "INVALID_COMMAND", 15);
                break;
        }
    }
cleanup:
    // Clean up connection resources
    SSL_shutdown(ssl);
    close(client_fd);
    SSL_free(ssl);
    return NULL;
}

// Main server function
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    server_state_t state;

    // Set up signal handlers for graceful shutdown
    signal(SIGINT, handle_shutdown);  // Ctrl+C
    signal(SIGTERM, handle_shutdown); // kill command
    
    // Initialize synchronization primitives
    pthread_rwlock_init(&download_lock, NULL);  // RWLock for downloads
    
    // Initialize semaphore for uploads (1 = unlocked, 0 = locked)
    if (sem_init(&upload_sem, 0, 1) != 0) {
        perror("sem_init failed");
        exit(EXIT_FAILURE);
    }

    // Initialize user database
    if (!init_database(&state)) {
        fprintf(stderr, "Failed to initialize database\n");
        return EXIT_FAILURE;
    }
    
    // Set up SSL/TLS
    SSL_CTX *ctx = create_ssl_context();
    load_certificates(ctx, "cert.pem", "key.pem");
    
    // Create thread pool
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_create(&thread_pool[i], NULL, thread_function, NULL);
    }
    
    // Create server socket
    int master_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (master_fd < 0) {
        perror("socket creation failed");
        return EXIT_FAILURE;
    }
    
    // Set socket options for reuse
    int opt = 1;
    if (setsockopt(master_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        return EXIT_FAILURE;
    }
    
    // Bind socket to port
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(master_fd, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
        perror("bind failed");
        return EXIT_FAILURE;
    }
    
    // Start listening for connections
    if (listen(master_fd, 10) < 0) {
        perror("listen failed");
        return EXIT_FAILURE;
    }
    
    printf("Server started on port %d\n", SERVER_PORT);
    
    // Main server loop
    while (!shutdown_server) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        // Accept new client connection
        int client_fd = accept(master_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept failed");
            continue;
        }
        
        printf("New connection from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // Create SSL connection
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        
        // Perform SSL handshake
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_fd);
            SSL_free(ssl);
            continue;
        }
        
        // Add client to work queue
        client_info_t client = { client_fd, ssl, &state, "", "", "" };
        enqueue_client(client);
    }
     
    // Cleanup on shutdown
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_cancel(thread_pool[i]);
        pthread_join(thread_pool[i], NULL);
    }
     
    close(master_fd);
    SSL_CTX_free(ctx);
    sqlite3_close(state.db);
     
    // Clean up any zombie processes
    while (waitpid(-1, NULL, WNOHANG) > 0);
     
    return 0;
}
