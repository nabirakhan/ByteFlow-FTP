#include "common.h"

void show_help() {
    printf("\nByteFlow-FTP Client Commands:\n");
    printf("  ls [path]          - List directory contents\n");
    printf("  get <file>         - Download file from server\n");
    printf("  put <file>         - Upload file to server\n");
    printf("  cd <path>          - Change directory\n");
    printf("  pwd                - Print current directory\n");
    printf("  help               - Show this help\n");
    printf("  quit               - Exit the client\n\n");
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <server_ip> <username>\n", argv[0]);
        return 1;
    }
    
    // Get password securely
    char password[50];
    printf("Password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0';
    
    // Initialize SSL
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    
    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        return 1;
    }
    
    // Connect to server
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, argv[1], &server_addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
        perror("connection failed");
        return 1;
    }
    
    // Create SSL connection
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    
    // Authenticate
    auth_struct_t auth;
    strncpy(auth.username, argv[2], 50);
    strncpy(auth.password, password, 50);
    
    SSL_write(ssl, &auth, sizeof(auth_struct_t));
    
    char auth_response[20];
    SSL_read(ssl, auth_response, sizeof(auth_response));
    auth_response[sizeof(auth_response)-1] = '\0';
    
    if (strcmp(auth_response, "AUTH_SUCCESS") != 0) {
        printf("Authentication failed\n");
        SSL_shutdown(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return 1;
    }
    
    printf("Connected to ByteFlow-FTP server\n");
    show_help();
    
    // Main command loop
    char input[256];
    char current_dir[MAX_PATH_LENGTH] = "";
    
    while (1) {
        printf("ftp> ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        
        if (strlen(input) == 0) continue;
        
        char *cmd = strtok(input, " ");
        char *arg = strtok(NULL, " ");
        
        if (strcmp(cmd, "quit") == 0) {
            break;
        }
        else if (strcmp(cmd, "help") == 0) {
            show_help();
        }
        else if (strcmp(cmd, "ls") == 0) {
            command_t cmd_pkt = {0};
            if (arg) strncpy(cmd_pkt.path, arg, MAX_PATH_LENGTH);
            SSL_write(ssl, &cmd_pkt, sizeof(command_t));
            
            char buffer[BUFFER_SIZE];
            while (1) {
                int bytes = SSL_read(ssl, buffer, BUFFER_SIZE-1);
                if (bytes <= 0) break;
                
                buffer[bytes] = '\0';
                if (strcmp(buffer, "END_LIST") == 0) break;
                
                printf("%s", buffer);
            }
            printf("\n");
        }
        else if (strcmp(cmd, "get") == 0 && arg) {
            command_t cmd_pkt = {1};
            strncpy(cmd_pkt.path, arg, MAX_PATH_LENGTH);
            SSL_write(ssl, &cmd_pkt, sizeof(command_t));
            
            file_transfer_t ft;
            SSL_read(ssl, &ft, sizeof(file_transfer_t));
            
            if (ft.filesize == -1) {
                printf("File not found on server\n");
                continue;
            }
            
            FILE *file = fopen(arg, "wb");
            if (!file) {
                printf("Failed to create local file\n");
                continue;
            }
            
            printf("Downloading %s (%.2f KB)...\n", arg, (float)ft.filesize/1024);
            
            char buffer[BUFFER_SIZE];
            long remaining = ft.filesize;
            while (remaining > 0) {
                int to_read = remaining > BUFFER_SIZE ? BUFFER_SIZE : remaining;
                int bytes = SSL_read(ssl, buffer, to_read);
                if (bytes <= 0) break;
                fwrite(buffer, 1, bytes, file);
                remaining -= bytes;
            }
            
            fclose(file);
            printf("Download complete\n");
        }
        else if (strcmp(cmd, "put") == 0 && arg) {
            FILE *file = fopen(arg, "rb");
            if (!file) {
                printf("File not found locally\n");
                continue;
            }
            
            fseek(file, 0, SEEK_END);
            long filesize = ftell(file);
            rewind(file);
            
            command_t cmd_pkt = {2};
            strncpy(cmd_pkt.path, arg, MAX_PATH_LENGTH);
            SSL_write(ssl, &cmd_pkt, sizeof(command_t));
            
            file_transfer_t ft;
            strncpy(ft.filename, arg, MAX_PATH_LENGTH);
            ft.filesize = filesize;
            SSL_write(ssl, &ft, sizeof(file_transfer_t));
            
            char response[20];
            SSL_read(ssl, response, sizeof(response));
            response[sizeof(response)-1] = '\0';
            
            if (strcmp(response, "UPLOAD_START") != 0) {
                printf("Server refused upload\n");
                fclose(file);
                continue;
            }
            
            printf("Uploading %s (%.2f KB)...\n", arg, (float)filesize/1024);
            
            char buffer[BUFFER_SIZE];
            size_t bytes_read;
            while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
                SSL_write(ssl, buffer, bytes_read);
            }
            
            fclose(file);
            
            SSL_read(ssl, response, sizeof(response));
            response[sizeof(response)-1] = '\0';
            
            if (strcmp(response, "UPLOAD_COMPLETE") == 0) {
                printf("Upload complete\n");
            } else {
                printf("Upload failed\n");
            }
        }
        else {
            printf("Unknown command. Type 'help' for available commands.\n");
        }
    }
    
    SSL_shutdown(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}