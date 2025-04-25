#include "common.h"

void show_help() {
    printf("\nByteFlow-FTP Client Commands:\n");
    printf("  ls [path]          - List directory contents\n");
    printf("  get <file>         - Download file from server\n");
    printf("  put <file>         - Upload file to server\n");
    printf("  cd <path>          - Change directory\n");
    printf("  pwd                - Print current directory\n");
    printf("  mkdir <name>       - Create a new directory\n");
    printf("  rmdir <name>       - Remove a directory\n");
    printf("  help               - Show this help\n");
    printf("  quit               - Exit the client\n\n");
}

void handle_admin_commands(SSL *ssl) {
    char input[256];
    printf("Admin commands:\n");
    printf("  adduser <username> <password> <homedir(server side)>\n"
        "  (Input the server directory you want to make available to clients)\n");
    printf("  deluser <username>\n");
    printf("  listusers           - List all users\n");
    printf("  exit                - Exit admin mode\n\n");
    
    while (1) {
        printf("admin> ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        
        if (strcmp(input, "exit") == 0) break;
        
        char *cmd = strtok(input, " ");
        if (strcmp(cmd, "adduser") == 0) {
            char *username = strtok(NULL, " ");
            char *password = strtok(NULL, " ");
            char *homedir = strtok(NULL, " ");
            
            if (username && password && homedir) {
                command_t cmd_pkt = {7, "", "", "", "", ""};  
                strncpy(cmd_pkt.username, username, 50);
                strncpy(cmd_pkt.password, password, 50);
                strncpy(cmd_pkt.home_dir, homedir, MAX_PATH_LENGTH);
                SSL_write(ssl, &cmd_pkt, sizeof(command_t));
                printf("laa");
                
                char response[20];
                SSL_read(ssl, response, sizeof(response));
                response[sizeof(response)-1] = '\0';
                printf("%s\n", response);
            } else {
                printf("Usage: adduser <username> <password> <homedir(server side)>\n");
            }
        } else if (strcmp(cmd, "deluser") == 0) {
            char *username = strtok(NULL, " ");
            
            if (username) {
                command_t cmd_pkt = {8, "", "", "", "", ""};
                strncpy(cmd_pkt.username, username, 50);
                
                SSL_write(ssl, &cmd_pkt, sizeof(command_t));
                
                char response[20];
                SSL_read(ssl, response, sizeof(response));
                response[sizeof(response)-1] = '\0';
                printf("%s\n", response);
            } else {
                printf("Usage: deluser <username>\n");
            }
        } else if (strcmp(cmd, "listusers") == 0) {
            command_t cmd_pkt = {9, "", "", "", "", ""};
            SSL_write(ssl, &cmd_pkt, sizeof(command_t));
            
            char buffer[512];
            printf("\n%-20s %s\n", "USERNAME", "HOME DIRECTORY");
            printf("-------------------- --------------------\n");
            
            while (1) {
                int bytes = SSL_read(ssl, buffer, sizeof(buffer)-1);
                if (bytes <= 0) break;
                
                buffer[bytes] = '\0';
                if (strcmp(buffer, "USER_LIST_END") == 0) break;
                if (strcmp(buffer, "USER_LIST_START") == 0) continue;
                if (strcmp(buffer, "PERMISSION_DENIED") == 0) {
                    printf("Permission denied\n");
                    break;
                }
                
                printf("%s\n", buffer);
            }
            printf("\n");
        } else {
            printf("Unknown admin command\n");
        }
    }
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
    auth_shared_t auth;
    strncpy(auth.username, argv[2], 50);
    strncpy(auth.password, password, 50);
    
    SSL_write(ssl, &auth, sizeof(auth_shared_t));
    
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

    // Check for admin
    if (strcmp(argv[2], "admin") == 0) {
        handle_admin_commands(ssl);
    }
    
    // Main command loop
    char input[256];
    
    while (1) {
        printf("user> ");
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
            command_t cmd_pkt = {0, "", "", "", "", ""}; 
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
            command_t cmd_pkt = {1, "", "", "", "", ""};  
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
            
            command_t cmd_pkt = {2, "", "", "", "", ""};  
            strncpy(cmd_pkt.path, arg, MAX_PATH_LENGTH);
            SSL_write(ssl, &cmd_pkt, sizeof(command_t));
            
            file_transfer_t ft;
            strncpy(ft.filename, arg, MAX_PATH_LENGTH);
            ft.filesize = filesize;
            SSL_write(ssl, &ft, sizeof(file_transfer_t));
            
            char response[20];
            int bytes = SSL_read(ssl, response, sizeof(response) - 1); 

            if (bytes > 0) {
                response[bytes] = '\0';  
            }
            
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
        else if (strcmp(cmd, "cd") == 0) {
            command_t cmd_pkt = {3, "", "", "", "", ""}; 
            if (arg) {
                strncpy(cmd_pkt.path, arg, MAX_PATH_LENGTH);
            } else {
                // If no arg provided, change to home directory
                strncpy(cmd_pkt.path, "~", MAX_PATH_LENGTH);
            }
            
            SSL_write(ssl, &cmd_pkt, sizeof(command_t));
            
            char response[32];
            int bytes = SSL_read(ssl, response, sizeof(response));
            if (bytes > 0) {
                response[bytes] = '\0';
                if (strcmp(response, "CD_SUCCESS") != 0) {
                    printf("Error: %s\n", response);
                }
            }

            memset(&cmd_pkt, 0, sizeof(command_t));
            cmd_pkt.type = 4; 
            SSL_write(ssl, &cmd_pkt, sizeof(command_t));

            char path[MAX_PATH_LENGTH];
            bytes = SSL_read(ssl, path, sizeof(path));
            if (bytes > 0) {
                path[bytes] = '\0';
                printf("Current directory: %s\n", path);
            }
        }
        else if (strcmp(cmd, "pwd") == 0) {
            command_t cmd_pkt = {4, "", "", "", "", ""}; 
            SSL_write(ssl, &cmd_pkt, sizeof(command_t));
            
            char path[MAX_PATH_LENGTH];
            int bytes = SSL_read(ssl, path, sizeof(path));
            if (bytes > 0) {
                path[bytes] = '\0';
                printf("Current directory: %s\n", path);
            }
        }
        else if (strcmp(cmd, "mkdir") == 0 && arg) {
            command_t cmd_pkt = {5, "", "", "", "", ""}; 
            strncpy(cmd_pkt.path, arg, MAX_PATH_LENGTH);
            SSL_write(ssl, &cmd_pkt, sizeof(command_t));
        
            char response[BUFFER_SIZE];
            int bytes = SSL_read(ssl, response, sizeof(response)-1);
            if (bytes > 0) {
                response[bytes] = '\0';
                printf("%s\n", response);
            }
        }
        else if (strcmp(cmd, "rmdir") == 0 && arg) {
            command_t cmd_pkt = {6, "", "", "", "", ""}; 
            strncpy(cmd_pkt.path, arg, MAX_PATH_LENGTH);
            SSL_write(ssl, &cmd_pkt, sizeof(command_t));
        
            char response[BUFFER_SIZE];
            int bytes = SSL_read(ssl, response, sizeof(response)-1);
            if (bytes > 0) {
                response[bytes] = '\0';
                printf("%s\n", response);
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
