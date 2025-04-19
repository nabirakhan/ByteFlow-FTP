/*
    Enhanced FTP client with better concurrency and memory management
*/
#include "myftp.h"
#include <pthread.h>
#include <semaphore.h>

// Shared data structure with synchronization
typedef struct {
    char server_IP[1024];
    int server_port_number;
    char login_id[1024];
    char login_pw[1024];
    char target_filename[1024];
    int connected;
    int authenticated;
    pthread_mutex_t lock;
    sem_t sem_conn;
} ClientState;

// Initialize client state
void init_client_state(ClientState *state) {
    memset(state->server_IP, 0, sizeof(state->server_IP));
    state->server_port_number = 0;
    memset(state->login_id, 0, sizeof(state->login_id));
    memset(state->login_pw, 0, sizeof(state->login_pw));
    memset(state->target_filename, 0, sizeof(state->target_filename));
    state->connected = 0;
    state->authenticated = 0;
    pthread_mutex_init(&state->lock, NULL);
    sem_init(&state->sem_conn, 0, 1);
}

// Cleanup client state
void cleanup_client_state(ClientState *state) {
    pthread_mutex_destroy(&state->lock);
    sem_destroy(&state->sem_conn);
}

int return_option(char str[]) {
    if (strcasecmp(str, "open") == 0) return 1;
    if (strcasecmp(str, "auth") == 0) return 2;
    if (strcasecmp(str, "ls") == 0) return 3;
    if (strcasecmp(str, "get") == 0) return 4;
    if (strcasecmp(str, "put") == 0) return 5;
    return 0;
}

// Thread-safe connection handling
void handle_open_connection(ClientState *state, int *newSocket) {
    sem_wait(&state->sem_conn);
    
    if (state->connected) {
        printf("Already connected to %s:%d\n", state->server_IP, state->server_port_number);
        sem_post(&state->sem_conn);
        return;
    }

    printf("Opening %s at port %d... ", state->server_IP, state->server_port_number);
    
    *newSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (*newSocket == -1) {
        perror("Error: Client - Could not create socket");
        sem_post(&state->sem_conn);
        return;
    }

    struct sockaddr_in server;
    server.sin_addr.s_addr = inet_addr(state->server_IP);
    server.sin_family = AF_INET;
    server.sin_port = htons(state->server_port_number);

    if (connect(*newSocket, (struct sockaddr *)&server, sizeof(server)) < 0 ) {
        perror("Error: Client - Connection failed");
        close(*newSocket);
        sem_post(&state->sem_conn);
        return;
    }

    struct message_s send_message;
    send_message.protocol[0] = 0xe3;
    strcat(send_message.protocol, "myftp");
    send_message.type = 0xA1;
    send_message.length = 12;
    memset(send_message.payload, '\0', 1024);

    if (send(*newSocket, (char *)&send_message, send_message.length, 0) != send_message.length) {
        perror("Error sending OPEN_CONN_REQUEST");
        close(*newSocket);
        sem_post(&state->sem_conn);
        return;
    }

    struct message_s recv_message;
    if (recv(*newSocket, (char *)&recv_message, sizeof(struct message_s), 0) <= 0) {
        perror("Error receiving OPEN_CONN_REPLY");
        close(*newSocket);
        sem_post(&state->sem_conn);
        return;
    }

    if (recv_message.status == '0') {
        printf("Error: Server connection failed.\n");
        close(*newSocket);
    } else {
        printf("Client - Server connection accepted.\n");
        state->connected = 1;
    }

    sem_post(&state->sem_conn);
}

// Thread-safe authentication
void handle_authentication(ClientState *state, int newSocket) {
    pthread_mutex_lock(&state->lock);
    
    if (state->authenticated) {
        printf("Already authenticated as %s\n", state->login_id);
        pthread_mutex_unlock(&state->lock);
        return;
    }

    struct message_s send_message;
    send_message.protocol[0] = 0xe3;
    strcat(send_message.protocol, "myftp");
    send_message.type = 0xA3;
    send_message.length = 12 + strlen(state->login_id) + strlen(state->login_pw) + 1;
    strcpy(send_message.payload, state->login_id);
    strcat(send_message.payload, " ");
    strcat(send_message.payload, state->login_pw);

    if (send(newSocket, (char *)&send_message, send_message.length, 0) != send_message.length) {
        perror("Error sending AUTH_REQUEST");
        pthread_mutex_unlock(&state->lock);
        return;
    }

    struct message_s recv_message;
    if (recv(newSocket, (char *)&recv_message, sizeof(struct message_s), 0) <= 0) {
        perror("Error receiving AUTH_REPLY");
        pthread_mutex_unlock(&state->lock);
        return;
    }

    if (recv_message.type != 0xA4) {
        printf("Error: Client - Wrong header received\n");
        pthread_mutex_unlock(&state->lock);
        return;
    }

    state->authenticated = (recv_message.status == 1);
    if (state->authenticated) {
        printf("Authentication granted.\n");
    } else {
        printf("Authentication FAILED.\n");
    }

    pthread_mutex_unlock(&state->lock);
}

// File transfer functions with error handling
int download_file(int newSocket, FILE *fb) {
    struct message_s data_message;
    char correct_type = 0xFF;
    size_t bytes_received = 0;

    do {
        if (recv(newSocket, (char *)&data_message, sizeof(struct message_s), 0) <= 0) {
            perror("Error receiving file data");
            return -1;
        }

        if (data_message.type != correct_type) {
            printf("Error: Wrong data header received\n");
            return -1;
        }

        size_t payload_size = data_message.length - 12;
        if (fwrite(data_message.payload, 1, payload_size, fb) != payload_size) {
            perror("Error writing to file");
            return -1;
        }
        bytes_received += payload_size;

    } while (data_message.status != 0);

    printf("Received %zu bytes\n", bytes_received);
    return 0;
}

int upload_file(int newSocket, FILE *fb) {
    struct message_s data_message;
    int size;
    size_t bytes_sent = 0;

    data_message.protocol[0] = 0xe3;
    strcat(data_message.protocol, "myftp");
    data_message.type = 0xFF;
    data_message.status = 1;

    do {
        size = fread(data_message.payload, 1, 1024, fb);
        if (ferror(fb)) {
            perror("Error reading file");
            return -1;
        }

        if (size < 1024) {
            if (feof(fb)) {
                data_message.status = 0;
            } else {
                perror("Error reading file");
                return -1;
            }
        }

        data_message.length = 12 + size;
        if (send(newSocket, (char *)&data_message, sizeof(struct message_s), 0) != sizeof(struct message_s)) {
            perror("Error sending file data");
            return -1;
        }
        bytes_sent += size;

    } while (data_message.status != 0);

    printf("Sent %zu bytes\n", bytes_sent);
    return 0;
}

int main(int argc, char *argv[]) {
    ClientState state;
    init_client_state(&state);
    
    int newSocket = -1;
    int quit = 0;
    char client_command[1024];
    char *token;
    char *thread_safety;

    while (!quit) {
        printf("Client > ");
        if (!fgets(client_command, sizeof(client_command), stdin)) {
            break;
        }
        client_command[strcspn(client_command, "\n")] = '\0';

        if (strcasecmp(client_command, "quit") == 0) {
            quit = 1;
            continue;
        }

        token = strtok_r(client_command, " \n", &thread_safety);
        if (!token) {
            printf("Error: Invalid command!\n");
            continue;
        }

        switch (return_option(token)) {
            case 1: { // open
                char temp_ip[1024];
                int temp_port;

                token = strtok_r(NULL, " \n", &thread_safety);
                if (!token) {
                    printf("Usage: open SERVER_IP PORT_NUMBER\n");
                    continue;
                }
                strncpy(temp_ip, token, sizeof(temp_ip) - 1);

                token = strtok_r(NULL, " \n", &thread_safety);
                if (!token) {
                    printf("Usage: open SERVER_IP PORT_NUMBER\n");
                    continue;
                }
                temp_port = atoi(token);
                if (temp_port <= 0) {
                    printf("Error: Bad Port Number\n");
                    continue;
                }

                pthread_mutex_lock(&state.lock);
                strncpy(state.server_IP, temp_ip, sizeof(state.server_IP) - 1);
                state.server_port_number = temp_port;
                pthread_mutex_unlock(&state.lock);

                handle_open_connection(&state, &newSocket);
                break;
            }
            
            case 2: { // auth
                char temp_id[1024], temp_pw[1024];

                token = strtok_r(NULL, " \n", &thread_safety);
                if (!token) {
                    printf("Usage: auth USER_ID USER_PASSWORD\n");
                    continue;
                }
                strncpy(temp_id, token, sizeof(temp_id) - 1);

                token = strtok_r(NULL, " \n", &thread_safety);
                if (!token) {
                    printf("Usage: auth USER_ID USER_PASSWORD\n");
                    continue;
                }
                strncpy(temp_pw, token, sizeof(temp_pw) - 1);

                pthread_mutex_lock(&state.lock);
                strncpy(state.login_id, temp_id, sizeof(state.login_id) - 1);
                strncpy(state.login_pw, temp_pw, sizeof(state.login_pw) - 1);
                pthread_mutex_unlock(&state.lock);

                handle_authentication(&state, newSocket);
                break;
            }
            
            case 3: { // ls
                if (!state.connected) {
                    printf("Error: No connection established\n");
                    continue;
                }
                if (!state.authenticated) {
                    printf("Error: Not authenticated\n");
                    continue;
                }

                struct message_s send_message;
                send_message.protocol[0] = 0xe3;
                strcat(send_message.protocol, "myftp");
                send_message.type = 0xA5;
                send_message.length = 12;

                if (send(newSocket, (char *)&send_message, send_message.length, 0) != send_message.length) {
                    perror("Error sending LIST_REQUEST");
                    continue;
                }

                struct message_s recv_message;
                if (recv(newSocket, (char *)&recv_message, sizeof(struct message_s), 0) <= 0) {
                    perror("Error receiving LIST_REPLY");
                    continue;
                }

                if (recv_message.type != 0xA6) {
                    printf("Error: Wrong header received\n");
                    continue;
                }

                printf("----- file list start -----\n%s----- file list end -----\n", recv_message.payload);
                break;
            }
            
            case 4: { // get
                if (!state.connected || !state.authenticated) {
                    printf("Error: Not connected or authenticated\n");
                    continue;
                }

                token = strtok_r(NULL, " \n", &thread_safety);
                if (!token) {
                    printf("Usage: get TARGET_FILENAME\n");
                    continue;
                }

                pthread_mutex_lock(&state.lock);
                strncpy(state.target_filename, token, sizeof(state.target_filename) - 1);
                pthread_mutex_unlock(&state.lock);

                printf("Downloading \"%s\"...\n", state.target_filename);

                struct message_s send_message;
                send_message.protocol[0] = 0xe3;
                strcat(send_message.protocol, "myftp");
                send_message.type = 0xA7;
                strcpy(send_message.payload, state.target_filename);
                send_message.length = 12 + strlen(state.target_filename);

                if (send(newSocket, (char *)&send_message, send_message.length, 0) != send_message.length) {
                    perror("Error sending GET_REQUEST");
                    continue;
                }

                struct message_s recv_message;
                if (recv(newSocket, (char *)&recv_message, sizeof(struct message_s), 0) <= 0) {
                    perror("Error receiving GET_REPLY");
                    continue;
                }

                if (recv_message.type != 0xA8) {
                    printf("Error: Wrong header received\n");
                    continue;
                }

                if (recv_message.status == 1) {
                    FILE *fb = fopen(state.target_filename, "wb");
                    if (!fb) {
                        perror("Error creating file");
                        continue;
                    }

                    if (download_file(newSocket, fb) < 0) {
                        printf("Error downloading file\n");
                        fclose(fb);
                        remove(state.target_filename);
                    } else {
                        printf("File downloaded successfully\n");
                        fclose(fb);
                    }
                } else {
                    printf("File does not exist on server\n");
                }
                break;
            }
            
            case 5: { // put
                if (!state.connected || !state.authenticated) {
                    printf("Error: Not connected or authenticated\n");
                    continue;
                }

                token = strtok_r(NULL, " \n", &thread_safety);
                if (!token) {
                    printf("Usage: put SOURCE_FILENAME\n");
                    continue;
                }

                pthread_mutex_lock(&state.lock);
                strncpy(state.target_filename, token, sizeof(state.target_filename) - 1);
                pthread_mutex_unlock(&state.lock);

                printf("Uploading \"%s\"...\n", state.target_filename);

                FILE *fb = fopen(state.target_filename, "rb");
                if (!fb) {
                    perror("Error opening file");
                    continue;
                }

                struct message_s send_message;
                send_message.protocol[0] = 0xe3;
                strcat(send_message.protocol, "myftp");
                send_message.type = 0xA9;
                strcpy(send_message.payload, state.target_filename);
                send_message.length = 12 + strlen(state.target_filename);

                if (send(newSocket, (char *)&send_message, send_message.length, 0) != send_message.length) {
                    perror("Error sending PUT_REQUEST");
                    fclose(fb);
                    continue;
                }

                struct message_s recv_message;
                if (recv(newSocket, (char *)&recv_message, sizeof(struct message_s), 0) <= 0) {
                    perror("Error receiving PUT_REPLY");
                    fclose(fb);
                    continue;
                }

                if (recv_message.type != 0xAA) {
                    printf("Error: Wrong header received\n");
                    fclose(fb);
                    continue;
                }

                if (upload_file(newSocket, fb)) {
                    printf("Error uploading file\n");
                } else {
                    printf("File uploaded successfully\n");
                }
                fclose(fb);
                break;
            }
            
            default:
                printf("Error: Unknown command\n");
                break;
        }
    }

    // Cleanup
    if (state.connected) {
        struct message_s send_message;
        send_message.protocol[0] = 0xe3;
        strcat(send_message.protocol, "myftp");
        send_message.type = 0xAB;
        send_message.length = 12;
        send(newSocket, (char *)&send_message, send_message.length, 0);
        close(newSocket);
    }

    cleanup_client_state(&state);
    printf("Thank you.\n");
    return 0;
}
