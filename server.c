#include "common.h"
#include <sys/select.h>
#include <sys/wait.h>

// Global variables
user_t users[MAX_USERS];
int user_count = 0;
pthread_t thread_pool[THREAD_POOL_SIZE];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_var = PTHREAD_COND_INITIALIZER;
int shutdown_server = 0;

typedef struct {
    int client_fd;
    SSL *ssl;
} client_info_t;

client_info_t client_queue[MAX_CLIENT_SUPPORTED];
int queue_front = 0;
int queue_rear = -1;
int queue_count = 0;

void initialize_users() {
    // In production, this should be loaded from a config file/database
    strcpy(users[0].username, "admin");
    strcpy(users[0].password, "password");
    strcpy(users[0].home_dir, "/mnt/e/linux/ftpp");
    user_count = 1;
}

int authenticate_user(char *username, char *password) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0 && 
            strcmp(users[i].password, password) == 0) {
            return 1;
        }
    }
    return 0;
}

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

void enqueue_client(client_info_t client) {
    pthread_mutex_lock(&mutex);
    if (queue_count < MAX_CLIENT_SUPPORTED) {
        queue_rear = (queue_rear + 1) % MAX_CLIENT_SUPPORTED;
        client_queue[queue_rear] = client;
        queue_count++;
        pthread_cond_signal(&cond_var);
    }
    pthread_mutex_unlock(&mutex);
}

client_info_t dequeue_client() {
    pthread_mutex_lock(&mutex);
    while (queue_count == 0 && !shutdown_server) {
        pthread_cond_wait(&cond_var, &mutex);
    }
    
    client_info_t client = { -1, NULL };
    if (!shutdown_server) {
        client = client_queue[queue_front];
        queue_front = (queue_front + 1) % MAX_CLIENT_SUPPORTED;
        queue_count--;
    }
    pthread_mutex_unlock(&mutex);
    return client;
}

void *thread_function(void *arg) {
    while (!shutdown_server) {
        client_info_t client = dequeue_client();
        if (client.client_fd != -1) {
            handle_client((void *)&client);
        }
    }
    return NULL;
}

void *handle_client(void *arg) {
    client_info_t *client = (client_info_t *)arg;
    int client_fd = client->client_fd;
    SSL *ssl = client->ssl;
    
    // Authentication
    auth_struct_t auth_data;
    int bytes = SSL_read(ssl, &auth_data, sizeof(auth_struct_t));
    if (bytes <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (!authenticate_user(auth_data.username, auth_data.password)) {
        SSL_write(ssl, "AUTH_FAIL", 9);
        goto cleanup;
    }
    SSL_write(ssl, "AUTH_SUCCESS", 12);

    // Main command loop
    command_t cmd;
    while (1) {
        bytes = SSL_read(ssl, &cmd, sizeof(command_t));
        if (bytes <= 0) break;

        switch (cmd.type) {
            case 0: {  // List directory
                DIR *dir;
                struct dirent *ent;
                char full_path[MAX_PATH_LENGTH];
                snprintf(full_path, MAX_PATH_LENGTH, "%s/%s", 
                         users[0].home_dir, cmd.path);

                 SSL_write(ssl, full_path, strlen(full_path));
                 SSL_write(ssl, "\n", 1);  // newline after path
                         
                
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
            case 1: {  // Download file
                file_transfer_t ft;
                strncpy(ft.filename, cmd.path, MAX_PATH_LENGTH);
                
                char full_path[MAX_PATH_LENGTH];
                snprintf(full_path, MAX_PATH_LENGTH, "%s/%s", 
                         users[0].home_dir, cmd.path);
                
                FILE *file = fopen(full_path, "rb");
                if (!file) {
                    ft.filesize = -1;
                    SSL_write(ssl, &ft, sizeof(file_transfer_t));
                    break;
                }
                
                fseek(file, 0, SEEK_END);
                ft.filesize = ftell(file);
                rewind(file);
                
                SSL_write(ssl, &ft, sizeof(file_transfer_t));
                
                char buffer[BUFFER_SIZE];
                size_t bytes_read;
                while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
                    SSL_write(ssl, buffer, bytes_read);
                }
                
                fclose(file);
                break;
            }
            case 2: {  // Upload file
                file_transfer_t ft;
                SSL_read(ssl, &ft, sizeof(file_transfer_t));
                
                char full_path[MAX_PATH_LENGTH];
                snprintf(full_path, MAX_PATH_LENGTH, "%s/%s", 
                         users[0].home_dir, ft.filename);
                
                FILE *file = fopen(full_path, "wb");
                if (!file) {
                    SSL_write(ssl, full_path, strlen(full_path));
                    SSL_write(ssl, "UPLOAD_FAIL", 11); 
                    break;
                }
                
                SSL_write(ssl, "UPLOAD_START", 12);
                
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
                break;
            }
            default:
                break;
        }
    }

cleanup:
    SSL_shutdown(ssl);
    close(client_fd);
    SSL_free(ssl);
    return NULL;
}

int main(int argc, char **argv) {
    initialize_users();
    
    // Initialize SSL
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
        exit(EXIT_FAILURE);
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(master_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }
    
    // Bind socket
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(master_fd, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    if (listen(master_fd, 10) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Server started on port %d\n", SERVER_PORT);
    
    // Main server loop
    while (!shutdown_server) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
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
        
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_fd);
            SSL_free(ssl);
            continue;
        }
        
        // Add client to queue
        client_info_t client = { client_fd, ssl };
        enqueue_client(client);
    }
    
    // Cleanup
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_join(thread_pool[i], NULL);
    }
    
    close(master_fd);
    SSL_CTX_free(ctx);
    return 0;
}