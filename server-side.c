#include "myftp.h"
#include <signal.h>
#include <time.h>

// Global variables
int serverPortNumber = 0;
int socketDescriptor = -1;
struct sockaddr_in serverAddr, clientAddr;
char one;

// Mutex for synchronization
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

// Semaphore for limiting concurrent connections
sem_t connection_semaphore;

// File cache
cache_entry_t file_cache[CACHE_SIZE];

// Log file descriptor
int log_fd = -1;

// Function to initialize the file cache
void init_file_cache() {
    pthread_mutex_lock(&cache_mutex);
    for (int i = 0; i < CACHE_SIZE; i++) {
        file_cache[i].is_valid = 0;
        file_cache[i].last_accessed = 0;
    }
    pthread_mutex_unlock(&cache_mutex);
}

// Function to cleanup the file cache
void cleanup_file_cache() {
    pthread_mutex_lock(&cache_mutex);
    // No dynamic memory to free in our simple cache
    pthread_mutex_unlock(&cache_mutex);
}

// Function to check if a file has the required permissions
int check_file_permissions(const char *filepath, int required_permissions) {
    struct stat file_stat;
    
    if (stat(filepath, &file_stat) < 0) {
        return 0; // File doesn't exist
    }
    
    // Check read permission
    if ((required_permissions & READ_PERMISSION) && !(file_stat.st_mode & S_IRUSR)) {
        return 0;
    }
    
    // Check write permission
    if ((required_permissions & WRITE_PERMISSION) && !(file_stat.st_mode & S_IWUSR)) {
        return 0;
    }
    
    // Check execute permission
    if ((required_permissions & EXECUTE_PERMISSION) && !(file_stat.st_mode & S_IXUSR)) {
        return 0;
    }
    
    return 1; // All required permissions are granted
}

// Function to set file permissions
void set_file_permissions(const char *filepath, int permissions) {
    mode_t mode = 0;
    
    // User permissions
    if (permissions & READ_PERMISSION)
        mode |= S_IRUSR;
    if (permissions & WRITE_PERMISSION)
        mode |= S_IWUSR;
    if (permissions & EXECUTE_PERMISSION)
        mode |= S_IXUSR;
    
    // Group permissions (same as user)
    if (permissions & READ_PERMISSION)
        mode |= S_IRGRP;
    if (permissions & WRITE_PERMISSION)
        mode |= S_IWGRP;
    if (permissions & EXECUTE_PERMISSION)
        mode |= S_IXGRP;
    
    // Others permissions (read-only)
    if (permissions & READ_PERMISSION)
        mode |= S_IROTH;
    
    chmod(filepath, mode);
}

// Function to log messages using named pipe
void log_message(const char *message) {
    pthread_mutex_lock(&log_mutex);
    
    // Open the named pipe for writing
    if (log_fd == -1) {
        // Create the named pipe if it doesn't exist
        mkfifo(LOG_FIFO, 0666);
        log_fd = open(LOG_FIFO, O_WRONLY | O_NONBLOCK);
    }
    
    if (log_fd != -1) {
        // Get current timestamp
        time_t now = time(NULL);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        // Format log message with timestamp
        char log_entry[1124]; // Timestamp + message + newline
        snprintf(log_entry, sizeof(log_entry), "[%s] %s\n", timestamp, message);
        
        // Write to the named pipe
        write(log_fd, log_entry, strlen(log_entry));
    }
    
    pthread_mutex_unlock(&log_mutex);
}

// Function to set process priority
void set_process_priority(int priority) {
    // Set process priority using nice (higher nice value = lower priority)
    nice(priority);
    
    // Alternative: Use real-time scheduling
    struct sched_param param;
    param.sched_priority = 50; // Mid-level priority
    
    if (priority < 0) {
        // Higher priority for important tasks
        sched_setscheduler(0, SCHED_RR, &param); // Round Robin scheduling
    } else {
        // Normal priority for regular tasks
        sched_setscheduler(0, SCHED_OTHER, &param); // Default scheduling
    }
}

// Function to encrypt data
int encrypt_data(unsigned char *plaintext, int plaintext_len, 
                unsigned char *key, unsigned char *iv, 
                unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) 
        return -1;

    // Initialize the encryption operation
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return -1;

    // Encrypt data
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;

    // Finalize encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return -1;
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// Function to decrypt data
int decrypt_data(unsigned char *ciphertext, int ciphertext_len, 
                unsigned char *key, unsigned char *iv, 
                unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    // Initialize the decryption operation
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return -1;

    // Decrypt data
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;

    // Finalize decryption
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        return -1;
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// Function to get a file from cache
void *get_cached_file(const char *filename) {
    pthread_mutex_lock(&cache_mutex);
    
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (file_cache[i].is_valid && strcmp(file_cache[i].filename, filename) == 0) {
            // Update last accessed time
            file_cache[i].last_accessed = time(NULL);
            
            void *content = malloc(file_cache[i].size);
            if (content) {
                memcpy(content, file_cache[i].content, file_cache[i].size);
                pthread_mutex_unlock(&cache_mutex);
                
                char log_msg[300];
                snprintf(log_msg, sizeof(log_msg), "Cache hit for file: %s", filename);
                log_message(log_msg);
                
                return content;
            }
        }
    }
    
    pthread_mutex_unlock(&cache_mutex);
    return NULL; // Not found in cache
}

// Function to add a file to cache
void cache_file(const char *filename, void *content, size_t size, int permissions) {
    if (size > MAX_CONTENT_SIZE) {
        return; // File too large for cache
    }
    
    pthread_mutex_lock(&cache_mutex);
    
    // Find the least recently used entry or an empty slot
    int oldest_idx = 0;
    time_t oldest_time = time(NULL);
    
    for (int i = 0; i < CACHE_SIZE; i++) {
        // If this is the file we're trying to cache, update it
        if (file_cache[i].is_valid && strcmp(file_cache[i].filename, filename) == 0) {
            memcpy(file_cache[i].content, content, size);
            file_cache[i].size = size;
            file_cache[i].last_accessed = time(NULL);
            file_cache[i].permissions = permissions;
            pthread_mutex_unlock(&cache_mutex);
            return;
        }
        
        // Find oldest entry
        if (!file_cache[i].is_valid || file_cache[i].last_accessed < oldest_time) {
            oldest_idx = i;
            oldest_time = file_cache[i].is_valid ? file_cache[i].last_accessed : 0;
        }
    }
    
    // Replace the oldest entry
    strncpy(file_cache[oldest_idx].filename, filename, MAX_FILENAME_LEN - 1);
    file_cache[oldest_idx].filename[MAX_FILENAME_LEN - 1] = '\0';
    memcpy(file_cache[oldest_idx].content, content, size);
    file_cache[oldest_idx].size = size;
    file_cache[oldest_idx].last_accessed = time(NULL);
    file_cache[oldest_idx].permissions = permissions;
    file_cache[oldest_idx].is_valid = 1;
    
    pthread_mutex_unlock(&cache_mutex);
    
    char log_msg[300];
    snprintf(log_msg, sizeof(log_msg), "File added to cache: %s", filename);
    log_message(log_msg);
}

// Function to send OPEN_CONN_REPLY
int send_open_conn_reply(int newSocket) {
    struct message_s reply_message;
    
    reply_message.protocol[0] = MYFTP_PROTOCOL_MAGIC;
    strcpy(reply_message.protocol + 1, MYFTP_PROTOCOL_NAME);
    reply_message.type = OPEN_CONN_REPLY;
    reply_message.status = 1;
    reply_message.length = 12;
    memset(reply_message.payload, '\0', 1024);
    
    send(newSocket, (char*)(&reply_message), reply_message.length, 0);
    return 0;
}

// Function to check authentication
int check_auth(char loginInfo[1024]) {
    FILE *fp;
    char usrnameAndPw[1024];
    
    if (fp = fopen("access.txt", "rb"), fp == NULL)
        return 0;
    else {
        while (fgets(usrnameAndPw, 1024, fp) != NULL) {
            usrnameAndPw[strlen(usrnameAndPw) - 1] = '\0';
            if (strcmp(loginInfo, usrnameAndPw) == 0) {
                // Login info verified
                fclose(fp);
                return 1;
            }
        }
    }
    fclose(fp);
    return 0;
}

// Function to send AUTH_REPLY
int send_auth_reply(int newSocket, int status) {
    struct message_s reply_message;
    
    reply_message.protocol[0] = MYFTP_PROTOCOL_MAGIC;
    strcpy(reply_message.protocol + 1, MYFTP_PROTOCOL_NAME);
    reply_message.type = AUTH_REPLY;
    reply_message.status = status;
    reply_message.length = 12;
    memset(reply_message.payload, '\0', 1024);
    
    send(newSocket, (char*)(&reply_message), reply_message.length, 0);
    return 0;
}

// Function to list directory and send LIST_REPLY
int list_dir_send_list_reply(int newSocket) {
    DIR *dir;
    struct dirent dp;
    struct dirent *ls_thread_safety;
    struct message_s reply_message;
    int return_code;
    
    pthread_mutex_lock(&file_mutex);
    
    memset(reply_message.payload, '\0', 1024);
    reply_message.protocol[0] = MYFTP_PROTOCOL_MAGIC;
    strcpy(reply_message.protocol + 1, MYFTP_PROTOCOL_NAME);
    reply_message.type = LIST_REPLY;
    
    // Read and store directory entries
    memset(reply_message.payload, '\0', 1024);
    dir = opendir("./filedir");
    
    if (dir == NULL) {
        printf("Error: Server - failed to open file directory");
        reply_message.length = 12 + strlen(reply_message.payload);
        send(newSocket, (char*)(&reply_message), reply_message.length, 0);
    } else {
        for (return_code = readdir_r(dir, &dp, &ls_thread_safety);
            ls_thread_safety != NULL && return_code == 0;
            return_code = readdir_r(dir, &dp, &ls_thread_safety)) {
            
            if (dp.d_type != 4) {
                // Get file permissions
                char filepath[1024];
                snprintf(filepath, sizeof(filepath), "./filedir/%s", dp.d_name);
                
                struct stat file_stat;
                if (stat(filepath, &file_stat) == 0) {
                    // Format: filename [permissions] size
                    char permissions[4] = "---";
                    
                    if (file_stat.st_mode & S_IRUSR)
                        permissions[0] = 'r';
                    if (file_stat.st_mode & S_IWUSR)
                        permissions[1] = 'w';
                    if (file_stat.st_mode & S_IXUSR)
                        permissions[2] = 'x';
                    
                    char file_info[1024];
                    snprintf(file_info, sizeof(file_info), "%s [%s] %ld bytes\n", 
                            dp.d_name, permissions, (long)file_stat.st_size);
                    
                    strcat(reply_message.payload, file_info);
                } else {
                    strcat(reply_message.payload, dp.d_name);
                    strcat(reply_message.payload, "\n");
                }
            }
        }
        
        // Send LIST_REPLY
        reply_message.length = 12 + strlen(reply_message.payload);
        send(newSocket, (char*)(&reply_message), reply_message.length, 0);
        
        closedir(dir);
    }
    
    pthread_mutex_unlock(&file_mutex);
    return 0;
}

// Function to send GET_REPLY
int send_get_reply(int newSocket, int status) {
    struct message_s reply_message;
    
    memset(reply_message.payload, '\0', 1024);
    reply_message.protocol[0] = MYFTP_PROTOCOL_MAGIC;
    strcpy(reply_message.protocol + 1, MYFTP_PROTOCOL_NAME);
    reply_message.type = GET_REPLY;
    reply_message.status = status;
    reply_message.length = 12;
    
    send(newSocket, (char *)(&reply_message), reply_message.length, 0);
    return 0;
}

// Function to send data over socket
int sendn(int newSocket, const void* buf, int buf_len) {
    int n_left = buf_len;
    int n;
    
    while (n_left > 0) {
        if ((n = send(newSocket, buf + (buf_len - n_left), n_left, 0)) < 0) {
            if (errno == EINTR)
                n = 0;
            else
                return -1;
        } else if (n == 0) {
            return 0;
        }
        n_left -= n;
    }
    
    return buf_len;
}

// Function to send file data
int send_file_data(int newSocket, FILE * fb, client_session_t *client) {
    struct message_s data_message;
    int size;
    unsigned char iv[16];  // Initialization vector for AES
    
    // Generate random IV for encryption
    RAND_bytes(iv, sizeof(iv));
    
    memset(data_message.payload, '\0', 1024);
    data_message.protocol[0] = MYFTP_PROTOCOL_MAGIC;
    strcpy(data_message.protocol + 1, MYFTP_PROTOCOL_NAME);
    data_message.type = FILE_DATA;
    data_message.status = 1;
    
    // First packet contains the IV
    memcpy(data_message.payload, iv, sizeof(iv));
    data_message.length = 12 + sizeof(iv);
    
    if (sendn(newSocket, (char *)&data_message, sizeof(struct message_s)) == -1) {
        printf("Error: Server - Failed to send IV\n");
        return -1;
    }
    
    // Reset file position
    fseek(fb, 0, SEEK_SET);
    
    // Use memory mapping for larger files
    struct stat file_stat;
    fstat(fileno(fb), &file_stat);
    
    if (file_stat.st_size > 10240) {  // If file size > 10KB, use mmap
        void *file_mapped = mmap(NULL, file_stat.st_size, PROT_READ, MAP_PRIVATE, fileno(fb), 0);
        
        if (file_mapped != MAP_FAILED) {
            // Send file in chunks
            size_t remaining = file_stat.st_size;
            size_t offset = 0;
            unsigned char encrypted[1024 + EVP_MAX_BLOCK_LENGTH];
            
            while (remaining > 0) {
                size = (remaining > 900) ? 900 : remaining;
                
                // Encrypt the chunk if client is authenticated
                if (client->is_authenticated) {
                    int encr_len = encrypt_data((unsigned char*)file_mapped + offset, size, 
                                             client->session_key, iv, encrypted);
                    
                    memcpy(data_message.payload, encrypted, encr_len);
                    data_message.length = 12 + encr_len;
                } else {
                    memcpy(data_message.payload, (char*)file_mapped + offset, size);
                    data_message.length = 12 + size;
                }
                
                // Set status to 0 for last packet
                if (remaining <= 900)
                    data_message.status = 0;
                
                if (sendn(newSocket, (char *)&data_message, sizeof(struct message_s)) == -1) {
                    printf("Error: Server - Failed to send file\n");
                    munmap(file_mapped, file_stat.st_size);
                    return -1;
                }
                
                offset += size;
                remaining -= size;
            }
            
            munmap(file_mapped, file_stat.st_size);
        } else {
            // Fallback to regular reading if mmap fails
            do {
                unsigned char buffer[900];
                unsigned char encrypted[1024 + EVP_MAX_BLOCK_LENGTH];
                
                size = fread(buffer, 1, 900, fb);
                
                // Encrypt the data if client is authenticated
                if (client->is_authenticated) {
                    int encr_len = encrypt_data(buffer, size, client->session_key, iv, encrypted);
                    memcpy(data_message.payload, encrypted, encr_len);
                    data_message.length = 12 + encr_len;
                } else {
                    memcpy(data_message.payload, buffer, size);
                    data_message.length = 12 + size;
                }
                
                if (size < 900)
                    data_message.status = 0;
                
                if (sendn(newSocket, (char *)&data_message, sizeof(struct message_s)) == -1) {
                    printf("Error: Server - Failed to send file\n");
                    return -1;
                }
            } while (data_message.status != 0);
        }
    } else {
        // Use standard file reading for smaller files
        do {
            unsigned char buffer[900];
            unsigned char encrypted[1024 + EVP_MAX_BLOCK_LENGTH];
            
            size = fread(buffer, 1, 900, fb);
            
            // Encrypt the data if client is authenticated
            if (client->is_authenticated) {
                int encr_len = encrypt_data(buffer, size, client->session_key, iv, encrypted);
                memcpy(data_message.payload, encrypted, encr_len);
                data_message.length = 12 + encr_len;
            } else {
                memcpy(data_message.payload, buffer, size);
                data_message.length = 12 + size;
            }
            
            if (size < 900)
                data_message.status = 0;
            
            if (sendn(newSocket, (char *)&data_message, sizeof(struct message_s)) == -1) {
                printf("Error: Server - Failed to send file\n");
                return -1;
            }
        } while (data_message.status != 0);
    }
    
    return 0;
}

// Function to receive data over socket
int recvn(int newSocket, void* buf, int buf_len) {
    int n_left = buf_len;
    int n = 0;
    
    while (n_left > 0) {
        if ((n = recv(newSocket, buf + (buf_len - n_left), n_left, 0)) < 0) {
            if (errno == EINTR)
                n = 0;
            else
                return -1;
        } else if (n == 0) {
            return 0;
        }
        n_left -= n;
    }
    
    return buf_len;
}

// Function to receive file data
int recv_file_data(int newSocket, char directory[], client_session_t *client) {
    struct message_s data_message;
    FILE *fb;
    unsigned char iv[16];
    int first_packet = 1;
    
    // Make sure directory exists
    pthread_mutex_lock(&file_mutex);
    
    fb = fopen(directory, "wb");
    if (fb != NULL) {
        do {
            if (recvn(newSocket, (char *)&data_message, sizeof(struct message_s)) == -1) {
                printf("Failed to receive.\n");
                fclose(fb);
                pthread_mutex_unlock(&file_mutex);
                return -1;
            }
            
            if (data_message.type != FILE_DATA) {
                printf("Error: Server - Incorrect type\n");
                fclose(fb);
                pthread_mutex_unlock(&file_mutex);
                return -1;
            }
            
            // Extract IV from first packet
            if (first_packet) {
                memcpy(iv, data_message.payload, sizeof(iv));
                first_packet = 0;
                continue;
            }
            
            // Decrypt data if client is authenticated
            if (client->is_authenticated) {
                unsigned char decrypted[1024];
                int decr_len = decrypt_data((unsigned char*)data_message.payload, 
                                          data_message.length - 12,
                                          client->session_key, iv, decrypted);
                
                fwrite(decrypted, 1, decr_len, fb);
            } else {
                fwrite(data_message.payload, 1, data_message.length - 12, fb);
            }
            
        } while (data_message.status != 0);
        
        fclose(fb);
        
        // Set default permissions for uploaded files
        set_file_permissions(directory, READ_PERMISSION | WRITE_PERMISSION);
        
        // Cache the file for future access
        struct stat file_stat;
        if (stat(directory, &file_stat) == 0 && file_stat.st_size <= MAX_CONTENT_SIZE) {
            FILE *cache_fb = fopen(directory, "rb");
            if (cache_fb != NULL) {
                void *content = malloc(file_stat.st_size);
                if (content && fread(content, 1, file_stat.st_size, cache_fb) == file_stat.st_size) {
                    cache_file(directory, content, file_stat.st_size, 
                              READ_PERMISSION | WRITE_PERMISSION);
                    free(content);
                }
                fclose(cache_fb);
            }
        }
    } else {
        printf("Cannot write file.\n");
        pthread_mutex_unlock(&file_mutex);
        return -1;
    }
    
    pthread_mutex_unlock(&file_mutex);
    return 0;
}

// Client handler thread function
void *client_handler(void *socketDescriptor) {
    // Get the socket descriptor
    int newSocket = *(int*) socketDescriptor;
    int readSize;
    struct message_s recv_message, send_message;
    int quit;
    FILE *fb;
    char target_filename[1024];
    char directory[1024 + 10];
    client_session_t client_session;
    
    // Initialize client session
    memset(&client_session, 0, sizeof(client_session_t));
    client_session.socket = newSocket;
    client_session.permission_level = PERM_NONE;
    client_session.is_authenticated = 0;
    
    // Generate random session key for this client
    RAND_bytes(client_session.session_key, sizeof(client_session.session_key));
    
    // Set lower priority for client handling threads
    set_process_priority(5);
    
    // Log new client connection
    char log_buffer[256];
    snprintf(log_buffer, sizeof(log_buffer), "New client connected on socket %d", newSocket);
    log_message(log_buffer);
    
    quit = 0;
    
    while (quit == 0) {
        // Get message from client
        memset(recv_message.payload, '\0', 1024);
        readSize = recv(newSocket, (char *)&recv_message, sizeof(struct message_s), 0);
        
        if (readSize <= 0) {
            // Client disconnected
            break;
        }
        
        // Print message type for debugging
        printf("recv_message.type is %x\n", recv_message.type);
        
        // Handle message based on type
        switch (recv_message.type) {
            case OPEN_CONN_REQUEST:
                printf("Server - OPEN_CONN_REQUEST received\n");
                send_open_conn_reply(newSocket);
                break;
                
            case AUTH_REQUEST:
                printf("Server - AUTH_REQUEST received\n");
                if (check_auth(recv_message.payload)) {
					struct message_s auth_reply;
					auth_reply.protocol[0] = MYFTP_PROTOCOL_MAGIC;
					strcpy(auth_reply.protocol + 1, MYFTP_PROTOCOL_NAME);
					auth_reply.type = AUTH_REPLY;
					auth_reply.status = 1;
					auth_reply.length = 12 + sizeof(client_session.session_key);
					memcpy(auth_reply.payload, client_session.session_key, sizeof(client_session.session_key));
					send(newSocket, &auth_reply, auth_reply.length, 0);
					client_session.is_authenticated = 1;
                    client_session.permission_level = PERM_FULL;
                    
                    // Log successful authentication
                    snprintf(log_buffer, sizeof(log_buffer), "Client %d authenticated successfully as %s", 
                             newSocket, recv_message.payload);
                    log_message(log_buffer);
                } else {
                    send_auth_reply(newSocket, 0);
                    
                    // Log failed authentication
                    snprintf(log_buffer, sizeof(log_buffer), "Client %d failed authentication attempt", newSocket);
                    log_message(log_buffer);
                }
                break;
                
            case LIST_REQUEST:
                printf("Server - LIST_REQUEST received\n");
                list_dir_send_list_reply(newSocket);
                break;
                
            case GET_REQUEST:
                printf("Server - GET_REQUEST received\n");
                
                // Check if client is authenticated for file operations
                if (!client_session.is_authenticated) {
                    send_get_reply(newSocket, 0);
                    log_message("Unauthenticated client attempted file download");
                    break;
                }
                
                strncpy(target_filename, recv_message.payload, sizeof(target_filename) - 1);
                target_filename[sizeof(target_filename) - 1] = '\0';
                
                // Construct file path
                memset(directory, '\0', sizeof(directory));
                sprintf(directory, "./filedir/%s", target_filename);
                
                // Check file permissions
                if (!check_file_permissions(directory, READ_PERMISSION)) {
                    send_get_reply(newSocket, 0);
                    
                    // Log permission denied
                    snprintf(log_buffer, sizeof(log_buffer), "Permission denied for file: %s", target_filename);
                    log_message(log_buffer);
                    break;
                }
                
                // Check if file exists in cache
                void *cached_content = get_cached_file(directory);
                if (cached_content) {
                    // Send successful reply
                    send_get_reply(newSocket, 1);
                    
                    // Create temporary file with cached content
                    char temp_path[1024];
                    snprintf(temp_path, sizeof(temp_path), "/tmp/myftp_cache_%d", newSocket);
                    FILE *temp_file = fopen(temp_path, "wb");
                    
                    if (temp_file) {
                        // Get cache entry to determine size
                        pthread_mutex_lock(&cache_mutex);
                        size_t cached_size = 0;
                        for (int i = 0; i < CACHE_SIZE; i++) {
                            if (file_cache[i].is_valid && strcmp(file_cache[i].filename, directory) == 0) {
                                cached_size = file_cache[i].size;
                                break;
                            }
                        }
                        pthread_mutex_unlock(&cache_mutex);
                        
                        // Write cached content to temp file
                        fwrite(cached_content, 1, cached_size, temp_file);
                        fclose(temp_file);
                        
                        // Send file from temp
                        temp_file = fopen(temp_path, "rb");
                        if (temp_file) {
                            send_file_data(newSocket, temp_file, &client_session);
                            fclose(temp_file);
                        }
                        
                        // Clean up
                        unlink(temp_path);
                        free(cached_content);
                        
                        // Log cache hit
                        snprintf(log_buffer, sizeof(log_buffer), "Sent cached file: %s", target_filename);
                        log_message(log_buffer);
                    } else {
                        // Fall back to regular file access
                        free(cached_content);
                        goto regular_file_access;
                    }
                } else {
                regular_file_access:
                    // Open file
                    fb = fopen(directory, "rb");
                    if (fb == NULL) {
                        send_get_reply(newSocket, 0);
                        
                        // Log file not found
                        snprintf(log_buffer, sizeof(log_buffer), "File not found: %s", target_filename);
                        log_message(log_buffer);
                    } else {
                        send_get_reply(newSocket, 1);
                        send_file_data(newSocket, fb, &client_session);
                        fclose(fb);
                        
                        // Log file sent
                        snprintf(log_buffer, sizeof(log_buffer), "Sent file: %s", target_filename);
                        log_message(log_buffer);
                    }
                }
                break;
                
            case PUT_REQUEST:
                printf("Server - PUT_REQUEST received\n");
                
                // Check if client is authenticated for file operations
                if (!client_session.is_authenticated) {
                    send_message.protocol[0] = MYFTP_PROTOCOL_MAGIC;
                    strcpy(send_message.protocol + 1, MYFTP_PROTOCOL_NAME);
                    send_message.type = PUT_REPLY;
                    send_message.status = 0;
                    send_message.length = 12;
                    memset(send_message.payload, '\0', 1024);
                    send(newSocket, (char *)&send_message, send_message.length, 0);
                    
                    log_message("Unauthenticated client attempted file upload");
                    break;
                }
                
                strncpy(target_filename, recv_message.payload, sizeof(target_filename) - 1);
                target_filename[sizeof(target_filename) - 1] = '\0';
                
                // Construct file path
                memset(directory, '\0', sizeof(directory));
                sprintf(directory, "./filedir/%s", target_filename);
                
                // Check if directory exists, create if not
                DIR *dir = opendir("./filedir");
                if (dir == NULL) {
                    mkdir("./filedir", 0777);
                } else {
                    closedir(dir);
                }
                
                // Check write permissions if file exists
                if (access(directory, F_OK) == 0 && !check_file_permissions(directory, WRITE_PERMISSION)) {
                    send_message.protocol[0] = MYFTP_PROTOCOL_MAGIC;
                    strcpy(send_message.protocol + 1, MYFTP_PROTOCOL_NAME);
                    send_message.type = PUT_REPLY;
                    send_message.status = 0;
                    send_message.length = 12;
                    memset(send_message.payload, '\0', 1024);
                    send(newSocket, (char *)&send_message, send_message.length, 0);
                    
                    // Log permission denied
                    snprintf(log_buffer, sizeof(log_buffer), "Permission denied for file upload: %s", target_filename);
                    log_message(log_buffer);
                    break;
                }
                
                // Send PUT_REPLY
                send_message.protocol[0] = MYFTP_PROTOCOL_MAGIC;
                strcpy(send_message.protocol + 1, MYFTP_PROTOCOL_NAME);
                send_message.type = PUT_REPLY;
                send_message.status = 1;
                send_message.length = 12;
                memset(send_message.payload, '\0', 1024);
                send(newSocket, (char *)&send_message, send_message.length, 0);
                
                // Receive file data
                if (recv_file_data(newSocket, directory, &client_session) == 0) {
                    // Log successful upload
                    snprintf(log_buffer, sizeof(log_buffer), "File uploaded successfully: %s", target_filename);
                    log_message(log_buffer);
                } else {
                    // Log failed upload
                    snprintf(log_buffer, sizeof(log_buffer), "File upload failed: %s", target_filename);
                    log_message(log_buffer);
                }
                break;
                
            case QUIT_REQUEST:
                printf("Server - QUIT_REQUEST received\n");
                
                // Send QUIT_REPLY
                send_message.protocol[0] = MYFTP_PROTOCOL_MAGIC;
                strcpy(send_message.protocol + 1, MYFTP_PROTOCOL_NAME);
                send_message.type = QUIT_REPLY;
                send_message.status = 1;
                send_message.length = 12;
                memset(send_message.payload, '\0', 1024);
                send(newSocket, (char *)&send_message, send_message.length, 0);
                
                // Log client disconnection
                snprintf(log_buffer, sizeof(log_buffer), "Client %d disconnected", newSocket);
                log_message(log_buffer);
                
                quit = 1;
                break;
                
            default:
                printf("Server - Unknown message type received: %x\n", recv_message.type);
                break;
        }
    }
    
    // Clean up
    close(newSocket);
    free(socketDescriptor);
    
    // Release semaphore
    sem_post(&connection_semaphore);
    
    return NULL;
}

// Signal handler for graceful shutdown
void handle_signal(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        printf("\nServer shutting down...\n");
        
        // Close the server socket
        if (socketDescriptor != -1) {
            close(socketDescriptor);
        }
        
        // Clean up resources
        cleanup_file_cache();
        
        // Close log file
        if (log_fd != -1) {
            close(log_fd);
            unlink(LOG_FIFO);
        }
        
        // Destroy mutexes and semaphores
        pthread_mutex_destroy(&file_mutex);
        pthread_mutex_destroy(&log_mutex);
        pthread_mutex_destroy(&cache_mutex);
        sem_destroy(&connection_semaphore);
        
        exit(0);
    }
}

// Main function
int main(int argc, char *argv[]) {
    struct sockaddr_in serverAddr, clientAddr;
    int clientAddrLen;
    int newSocket;
    pthread_t thread_id;
    
    // Check command line arguments
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }
    
    // Get port number from command line arguments
    serverPortNumber = atoi(argv[1]);
    
    // Initialize resources
    init_file_cache();
    
    // Initialize semaphore for connection limiting
    sem_init(&connection_semaphore, 0, 20); // Allow up to 20 concurrent connections
    
    // Set up signal handler
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Create socket
    socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (socketDescriptor == -1) {
        printf("Error: Server - Could not create socket\n");
        return 1;
    }
    
    // Setup server address structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(serverPortNumber);
    
    // Allow socket reuse
    setsockopt(socketDescriptor, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    
    // Bind socket to address
    if (bind(socketDescriptor, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        printf("Error: Server - Bind failed\n");
        return 1;
    }
    
    // Listen for incoming connections
    if (listen(socketDescriptor, 5) < 0) {
        printf("Error: Server - Listen failed\n");
        return 1;
    }
    
    // Set higher priority for the main thread
    set_process_priority(-10);
    
    // Create log directory if it doesn't exist
    mkfifo(LOG_FIFO, 0666);
    
    // Log server start
    char log_msg[256];
	snprintf(log_msg, sizeof(log_msg), "Server started on port %d", serverPortNumber);
	log_message(log_msg);  // Was previously "Server started on port " + serverPortNumber
    
    // Accept incoming connections
    while (1) {
        clientAddrLen = sizeof(struct sockaddr_in);
        
        // Wait for semaphore (connection limit)
        sem_wait(&connection_semaphore);
        
        // Accept connection
        newSocket = accept(socketDescriptor, (struct sockaddr *)&clientAddr, (socklen_t*)&clientAddrLen);
        if (newSocket < 0) {
            printf("Error: Server - Accept failed\n");
            sem_post(&connection_semaphore);
            continue;
        }
        
        printf("New connection accepted from %s:%d\n", 
               inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
        
        // Create thread to handle client
        int *client_sock = malloc(sizeof(int));
        *client_sock = newSocket;
        
        if (pthread_create(&thread_id, NULL, client_handler, (void *)client_sock) < 0) {
            printf("Error: Server - Could not create thread\n");
            close(newSocket);
            free(client_sock);
            sem_post(&connection_semaphore);
        } else {
            // Detach thread
            pthread_detach(thread_id);
        }
    }
    
    return 0;
}
