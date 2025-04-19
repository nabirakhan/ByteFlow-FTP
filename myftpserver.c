/*
    Enhanced FTP server with multiprocessing and synchronization
*/
#include "myftp.h"
#include <signal.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/wait.h>
#include <dirent.h>

#define MAX_CLIENTS 10

// Server configuration with synchronization
typedef struct {
    int server_port;
    int socket_fd;
    int active_clients;
    pthread_mutex_t client_count_lock;
    sem_t client_slots;
} ServerConfig;

// Client session data
typedef struct {
    int socket;
    struct sockaddr_in addr;
    pid_t pid;
    int authenticated;
    ServerConfig *config;
} ClientSession;

// Initialize server configuration
void init_server_config(ServerConfig *config, int port) {
    config->server_port = port;
    config->socket_fd = -1;
    config->active_clients = 0;
    pthread_mutex_init(&config->client_count_lock, NULL);
    sem_init(&config->client_slots, 0, MAX_CLIENTS);
}

// Cleanup server configuration
void cleanup_server_config(ServerConfig *config) {
    if (config->socket_fd != -1) {
        close(config->socket_fd);
    }
    pthread_mutex_destroy(&config->client_count_lock);
    sem_destroy(&config->client_slots);
}

// Signal handler for child processes
void sigchld_handler(int sig) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

// Thread-safe client counter
void increment_client_count(ServerConfig *config) {
    pthread_mutex_lock(&config->client_count_lock);
    config->active_clients++;
    printf("Active clients: %d\n", config->active_clients);
    pthread_mutex_unlock(&config->client_count_lock);
}

void decrement_client_count(ServerConfig *config) {
    pthread_mutex_lock(&config->client_count_lock);
    config->active_clients--;
    printf("Active clients: %d\n", config->active_clients);
    pthread_mutex_unlock(&config->client_count_lock);
}

// Authentication check
int check_auth(const char *loginInfo) {
    FILE *fp = fopen("access.txt", "r");
    if (!fp) return 0;

    char line[1024];
    int authenticated = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(loginInfo, line) == 0) {
            authenticated = 1;
            break;
        }
    }
    
    fclose(fp);
    return authenticated;
}

// Process client requests
void handle_client(ClientSession *session) {
    struct message_s recv_msg, send_msg;
    char directory[1024 + 10] = "./";
    
    printf("Client connected from %s:%d\n", 
           inet_ntoa(session->addr.sin_addr), 
           ntohs(session->addr.sin_port));

    while (1) {
        memset(&recv_msg, 0, sizeof(recv_msg));
        
        if (recv(session->socket, (char *)&recv_msg, sizeof(struct message_s), 0) <= 0) {
            perror("Receive error");
            break;
        }

        printf("Received message type: 0x%02X\n", recv_msg.type);

        switch (recv_msg.type) {
            case 0xA1: // OPEN_CONN_REQUEST
                printf("OPEN_CONN_REQUEST received\n");
                memset(&send_msg, 0, sizeof(send_msg));
                send_msg.protocol[0] = 0xe3;
                strcat(send_msg.protocol, "myftp");
                send_msg.type = 0xA2;
                send_msg.status = 1;
                send_msg.length = 12;
                
                if (send(session->socket, (char *)&send_msg, send_msg.length, 0) != send_msg.length) {
                    perror("Error sending OPEN_CONN_REPLY");
                }
                printf("OPEN_CONN_REPLY sent\n");
                break;

            case 0xA3: // AUTH_REQUEST
                printf("AUTH_REQUEST received\n");
                recv_msg.payload[recv_msg.length-12] = '\0';
                
                session->authenticated = check_auth(recv_msg.payload);
                printf("Authentication %s\n", session->authenticated ? "granted" : "failed");

                memset(&send_msg, 0, sizeof(send_msg));
                send_msg.protocol[0] = 0xe3;
                strcat(send_msg.protocol, "myftp");
                send_msg.type = 0xA4;
                send_msg.status = session->authenticated;
                send_msg.length = 12;
                
                if (send(session->socket, (char *)&send_msg, send_msg.length, 0) != send_msg.length) {
                    perror("Error sending AUTH_REPLY");
                }
                printf("AUTH_REPLY sent\n");
                break;

            case 0xA5: // LIST_REQUEST
                if (!session->authenticated) {
                    printf("Unauthorized LIST_REQUEST\n");
                    strcpy(send_msg.payload, "Not authenticated");
                    send_msg.length = 12 + strlen(send_msg.payload);
                    send(session->socket, (char *)&send_msg, send_msg.length, 0);
                    break;
                }

                printf("LIST_REQUEST received\n");
                DIR *dir;
                struct dirent *entry;
                
                memset(&send_msg, 0, sizeof(send_msg));
                send_msg.protocol[0] = 0xe3;
                strcat(send_msg.protocol, "myftp");
                send_msg.type = 0xA6;
                
                dir = opendir("./filedir");
                if (dir) {
                    while ((entry = readdir(dir)) != NULL) {
                        if (entry->d_type == DT_REG) { // Regular file
                            strcat(send_msg.payload, entry->d_name);
                            strcat(send_msg.payload, "\n");
                        }
                    }
                    closedir(dir);
                }
                send_msg.length = 12 + strlen(send_msg.payload);
                
                if (send(session->socket, (char *)&send_msg, send_msg.length, 0) != send_msg.length) {
                    perror("Error sending LIST_REPLY");
                }
                printf("LIST_REPLY sent\n");
                break;

            case 0xA7: // GET_REQUEST
                if (!session->authenticated) {
                    printf("Unauthorized GET_REQUEST\n");
                    strcpy(send_msg.payload, "Not authenticated");
                    send_msg.length = 12 + strlen(send_msg.payload);
                    send(session->socket, (char *)&send_msg, send_msg.length, 0);
                    break;
                }

                printf("GET_REQUEST received\n");
                recv_msg.payload[recv_msg.length-12] = '\0';
                
                memset(&send_msg, 0, sizeof(send_msg));
                send_msg.protocol[0] = 0xe3;
                strcat(send_msg.protocol, "myftp");
                send_msg.type = 0xA8;
                
                strcat(directory, recv_msg.payload);
                FILE *file = fopen(directory, "rb");
                if (file) {
                    send_msg.status = 1;
                    send_msg.length = 12;
                    
                    if (send(session->socket, (char *)&send_msg, send_msg.length, 0) != send_msg.length) {
                        perror("Error sending GET_REPLY");
                        fclose(file);
                        break;
                    }
                    printf("GET_REPLY sent\n");

                    struct message_s data_msg;
                    size_t bytes_sent = 0;
                    
                    data_msg.protocol[0] = 0xe3;
                    strcat(data_msg.protocol, "myftp");
                    data_msg.type = 0xFF;
                    data_msg.status = 1;

                    while (!feof(file)) {
                        size_t read_bytes = fread(data_msg.payload, 1, 1024, file);
                        if (ferror(file)) {
                            perror("File read error");
                            break;
                        }

                        data_msg.length = 12 + read_bytes;
                        if (feof(file)) {
                            data_msg.status = 0;
                        }

                        if (send(session->socket, (char *)&data_msg, sizeof(data_msg), 0) != sizeof(data_msg)) {
                            perror("Error sending file data");
                            break;
                        }
                        bytes_sent += read_bytes;
                    }
                    printf("Sent %zu bytes of file data\n", bytes_sent);
                    fclose(file);
                } else {
                    send_msg.status = 0;
                    send_msg.length = 12;
                    
                    if (send(session->socket, (char *)&send_msg, send_msg.length, 0) != send_msg.length) {
                        perror("Error sending GET_REPLY");
                    }
                    printf("GET_REPLY sent (file not found)\n");
                }
                break;

            case 0xA9: // PUT_REQUEST
                if (!session->authenticated) {
                    printf("Unauthorized PUT_REQUEST\n");
                    strcpy(send_msg.payload, "Not authenticated");
                    send_msg.length = 12 + strlen(send_msg.payload);
                    send(session->socket, (char *)&send_msg, send_msg.length, 0);
                    break;
                }

                printf("PUT_REQUEST received\n");
                recv_msg.payload[recv_msg.length-12] = '\0';
                
                memset(&send_msg, 0, sizeof(send_msg));
                send_msg.protocol[0] = 0xe3;
                strcat(send_msg.protocol, "myftp");
                send_msg.type = 0xAA;
                send_msg.length = 12;
                
                if (send(session->socket, (char *)&send_msg, send_msg.length, 0) != send_msg.length) {
                    perror("Error sending PUT_REPLY");
                    break;
                }
                printf("PUT_REPLY sent\n");

                strcat(directory, recv_msg.payload);
                FILE *out_file = fopen(directory, "wb");
                if (!out_file) {
                    perror("Error creating file");
                    break;
                }

                struct message_s data_msg;
                size_t bytes_received = 0;
                
                do {
                    if (recv(session->socket, (char *)&data_msg, sizeof(data_msg), 0) <= 0) {
                        perror("Error receiving file data");
                        break;
                    }

                    if (data_msg.type != 0xFF) {
                        printf("Invalid data packet type\n");
                        break;
                    }

                    size_t write_bytes = data_msg.length - 12;
                    if (fwrite(data_msg.payload, 1, write_bytes, out_file) != write_bytes) {
                        perror("Error writing to file");
                        break;
                    }
                    bytes_received += write_bytes;

                } while (data_msg.status != 0);

                printf("Received %zu bytes of file data\n", bytes_received);
                fclose(out_file);
                break;

            case 0xAB: // QUIT_REQUEST
                printf("QUIT_REQUEST received\n");
                memset(&send_msg, 0, sizeof(send_msg));
                send_msg.protocol[0] = 0xe3;
                strcat(send_msg.protocol, "myftp");
                send_msg.type = 0xAC;
                send_msg.length = 12;
                
                if (send(session->socket, (char *)&send_msg, send_msg.length, 0) != send_msg.length) {
                    perror("Error sending QUIT_REPLY");
                }
                printf("QUIT_REPLY sent\n");
                close(session->socket);
                return;

            default:
                printf("Invalid message type: 0x%02X\n", recv_msg.type);
                break;
        }
    }

    close(session->socket);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s PORT\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        printf("Invalid port number\n");
        return 1;
    }

    // Set up signal handling
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        return 1;
    }

    // Initialize server configuration
    ServerConfig config;
    init_server_config(&config, port);

    // Create socket
    config.socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (config.socket_fd == -1) {
        perror("socket");
        cleanup_server_config(&config);
        return 1;
    }

    // Set SO_REUSEADDR
    int opt = 1;
    if (setsockopt(config.socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        cleanup_server_config(&config);
        return 1;
    }

    // Bind socket
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(config.socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
        perror("bind");
        cleanup_server_config(&config);
        return 1;
    }

    // Listen for connections
    if (listen(config.socket_fd, SOMAXCONN)) {
        perror("listen");
        cleanup_server_config(&config);
        return 1;
    }

    printf("Server started on port %d\n", port);

    // Main server loop
    while (1) {
        // Wait for an available client slot
        sem_wait(&config.client_slots);

        ClientSession session;
        socklen_t client_len = sizeof(session.addr);
        
        session.socket = accept(config.socket_fd, (struct sockaddr *)&session.addr, &client_len);
        if (session.socket == -1) {
            perror("accept");
            sem_post(&config.client_slots);
            continue;
        }

        increment_client_count(&config);
        session.config = &config;
        session.authenticated = 0;

        // Fork a new process for this client
        pid_t pid = fork();
        if (pid == -1) {
            perror("fork");
            close(session.socket);
            decrement_client_count(&config);
            sem_post(&config.client_slots);
            continue;
        }

        if (pid == 0) { // Child process
            close(config.socket_fd);
            handle_client(&session);
            decrement_client_count(&config);
            sem_post(&config.client_slots);
            exit(0);
        } else { // Parent process
            close(session.socket);
        }
    }

    cleanup_server_config(&config);
    return 0;
}
