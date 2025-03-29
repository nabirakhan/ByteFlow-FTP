/*
    C ECHO client example using sockets
*/
#include "myftp.h"
#include <openssl/evp.h>
#include <openssl/err.h>

char server_IP[1024];
int server_port_number;

char login_id[1024];
char login_pw[1024];
unsigned char session_key[32];  // Store session key from server

char target_filename[1024];

struct message_s{
    char protocol[6];
    char type;      /* type (1 byte) */
    char status;    /* status (1 byte) */
    int length;     /* length (header + payload) (4 bytes) */
    char payload[1024]; /* payload */
} __attribute__ ((packed));


int return_option(char str[]){
    if( strcasecmp(str,"open") == 0 )   return 1;
    if( strcasecmp(str,"auth") == 0 )   return 2;
    if( strcasecmp(str,"ls") == 0 )     return 3;
    if( strcasecmp(str,"get") == 0 )    return 4;
    if( strcasecmp(str,"put") == 0 )    return 5;
    return 0;
}

void send_open_conn_request(int newSocket){
    struct message_s send_message;
    send_message.protocol[0] = MYFTP_PROTOCOL_MAGIC;
    strcpy(send_message.protocol+1, MYFTP_PROTOCOL_NAME);
    send_message.type = OPEN_CONN_REQUEST;
    send_message.length = 12;
    memset(send_message.payload, '\0', 1024);
    send(newSocket, (char *)&send_message, send_message.length, 0);
}

int recvn(int newSocket, void* buf, int buf_len){
    int n_left = buf_len;
    int n = 0;
    while (n_left > 0){
        if ((n = recv(newSocket, buf + (buf_len - n_left), n_left, 0)) < 0){
            if (errno == EINTR) n = 0;
            else return -1;
        } else if (n == 0) return 0;
        n_left -= n;
    }
    return buf_len;
}

int download_file(int newSocket, FILE * fb){
    struct message_s data_message;
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[16];
    int first_packet = 1;
    int plaintext_len, final_len;

    // Initialize crypto context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Error creating decryption context\n");
        return -1;
    }

    do {
        if (recvn(newSocket, &data_message, sizeof(struct message_s)) <= 0){
            printf("Error receiving file data\n");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        // First packet contains IV
        if(first_packet) {
            memcpy(iv, data_message.payload, sizeof(iv));
            if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, session_key, iv)) {
                printf("Decryption init failed\n");
                EVP_CIPHER_CTX_free(ctx);
                return -1;
            }
            first_packet = 0;
            continue;
        }

        unsigned char plaintext[1024 + EVP_MAX_BLOCK_LENGTH];
        int ciphertext_len = data_message.length - 12;
        
        if(!EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, 
                            (unsigned char*)data_message.payload, ciphertext_len)) {
            printf("Decryption failed\n");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        
        if(!EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &final_len)) {
            printf("Decryption final failed\n");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        plaintext_len += final_len;

        fwrite(plaintext, 1, plaintext_len, fb);

    } while(data_message.status != 0);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int sendn(int newSocket, const void* buf, int buf_len){
    int n_left = buf_len;
    int n;
    while(n_left > 0){
        if((n = send(newSocket, buf + (buf_len - n_left), n_left, 0)) < 0){
            if(errno == EINTR) n = 0;
            else return -1;
        } else if(n == 0) return 0;
        n_left -= n;
    }
    return buf_len;
}

int upload_file(int newSocket, FILE * fb){
    struct message_s data_message;
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    // Initialize crypto context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Error creating encryption context\n");
        return -1;
    }

    // Send IV first
    data_message.protocol[0] = MYFTP_PROTOCOL_MAGIC;
    strcpy(data_message.protocol+1, MYFTP_PROTOCOL_NAME);
    data_message.type = FILE_DATA;
    data_message.status = 1;
    data_message.length = 12 + sizeof(iv);
    memcpy(data_message.payload, iv, sizeof(iv));
    sendn(newSocket, &data_message, sizeof(struct message_s));

    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, session_key, iv)) {
        printf("Encryption init failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    do {
        unsigned char plaintext[1024], ciphertext[1024 + EVP_MAX_BLOCK_LENGTH];
        int size = fread(plaintext, 1, 1024, fb);
        int cipher_len, final_len;

        if(!EVP_EncryptUpdate(ctx, ciphertext, &cipher_len, plaintext, size)) {
            printf("Encryption failed\n");
            break;
        }
        
        if(!EVP_EncryptFinal_ex(ctx, ciphertext + cipher_len, &final_len)) {
            printf("Encryption final failed\n");
            break;
        }
        cipher_len += final_len;

        data_message.length = 12 + cipher_len;
        data_message.status = (size < 1024) ? 0 : 1;
        memcpy(data_message.payload, ciphertext, cipher_len);

        if(sendn(newSocket, &data_message, sizeof(struct message_s)) == -1){
            printf("Upload failed\n");
            break;
        }
    } while(data_message.status != 0);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

void send_quit_request(int newSocket, int *connected){
    struct message_s message, recv_message;
    if(*connected) {
        printf("Disconnecting... ");
        message.protocol[0] = MYFTP_PROTOCOL_MAGIC;
        strcpy(message.protocol+1, MYFTP_PROTOCOL_NAME);
        message.type = QUIT_REQUEST;
        message.length = 12;
        send(newSocket,(char *)&message,message.length, 0);
        recv(newSocket,(char*)&recv_message, sizeof(struct message_s), 0);
        if(recv_message.type == QUIT_REPLY) printf("Success!\n");
        else printf("Error!\n");
    }
    *connected = 0;
}

int main(int argc, char *argv[])
{
    char client_command[1024];
    int newSocket = -1;
    struct sockaddr_in server;
    struct message_s send_message, recv_message;
    int quit = 0;
    char* token;
    char temp_server_IP[1024];
    int temp_server_port_number;
    char temp_login_id[1024];
    char temp_login_pw[1024];
    FILE *fb;
    int connected = 0;
    int authenticated = 0;
    char *thread_safety;

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    while(!quit)
    {
        printf("Client > ");
        fgets(client_command, 1024, stdin);
        client_command[strlen(client_command)-1] = '\0';

        if(strcasecmp(client_command, "quit") != 0) 
        {
            token = strtok_r(client_command, " \n", &thread_safety);
            if(!token) {
                printf("Invalid command!\n");
                continue;
            }

            // Command validation checks
            if(!connected && return_option(token) > 1) {
                printf("Error: No connection established. Use 'open' first.\n");
                continue;
            }
            if(return_option(token) > 2 && !authenticated) {
                printf("Error: Authentication required. Use 'auth' first.\n");
                continue;
            }

            switch(return_option(token))
            {
                case 1: { // open
                    connected = 0;
                    token = strtok_r(NULL, " \n", &thread_safety);
                    if(token == NULL) {
                        printf("Usage: open SERVER_IP PORT_NUMBER\n");
                        continue;
                    }
                    strcpy(temp_server_IP, token);
                    
                    token = strtok_r(NULL, " \n", &thread_safety);
                    if(token == NULL) {
                        printf("Usage: open SERVER_IP PORT_NUMBER\n");
                        continue;
                    }
                    temp_server_port_number = atoi(token);
                    if(temp_server_port_number <= 0 || temp_server_port_number > 65535) {
                        printf("Error: Invalid port number\n");
                        continue;
                    }
                
                    // Create socket
                    newSocket = socket(AF_INET, SOCK_STREAM, 0);
                    if(newSocket < 0) {
                        perror("Socket creation failed");
                        continue;
                    }
                
                    // Configure server address
                    struct sockaddr_in server_addr;
                    memset(&server_addr, 0, sizeof(server_addr));
                    server_addr.sin_family = AF_INET;
                    server_addr.sin_port = htons(temp_server_port_number);
                    
                    // Convert IP address from text to binary form
                    if(inet_pton(AF_INET, temp_server_IP, &server_addr.sin_addr) <= 0) {
                        printf("Invalid address/Address not supported\n");
                        close(newSocket);
                        continue;
                    }
                
                    printf("Connecting to %s:%d... ", temp_server_IP, temp_server_port_number);
                    
                    // Connect to server
                    if(connect(newSocket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                        perror("Connection failed");
                        close(newSocket);
                        continue;
                    }
                
                    // Send OPEN_CONN_REQUEST
                    struct message_s conn_msg;
                    conn_msg.protocol[0] = MYFTP_PROTOCOL_MAGIC;
                    strcpy(conn_msg.protocol + 1, MYFTP_PROTOCOL_NAME);
                    conn_msg.type = OPEN_CONN_REQUEST;
                    conn_msg.length = 12;
                    memset(conn_msg.payload, 0, 1024);
                    
                    if(send(newSocket, &conn_msg, sizeof(conn_msg), 0) < 0) {
                        perror("Connection request failed");
                        close(newSocket);
                        continue;
                    }
                
                    // Receive OPEN_CONN_REPLY
                    struct message_s reply;
                    if(recv(newSocket, &reply, sizeof(reply), 0) < 0) {
                        perror("Connection response failed");
                        close(newSocket);
                        continue;
                    }
                
                    if(reply.type == OPEN_CONN_REPLY && reply.status == 1) {
                        connected = 1;
                        server_port_number = temp_server_port_number;
                        strcpy(server_IP, temp_server_IP);
                        printf("Connected successfully!\n");
                    } else {
                        printf("Server rejected connection\n");
                        close(newSocket);
                    }
                    break;
                }

                case 2: // auth
                {
                    // Get credentials
                    token = strtok_r(NULL, " \n", &thread_safety);
                    if(!token) {
                        printf("Usage: auth USERNAME PASSWORD\n");
                        break;
                    }
                    strcpy(temp_login_id, token);
                    
                    token = strtok_r(NULL, " \n", &thread_safety);
                    if(!token) {
                        printf("Usage: auth USERNAME PASSWORD\n");
                        break;
                    }
                    strcpy(temp_login_pw, token);

                    // Send auth request
                    memset(&send_message, 0, sizeof(send_message));
                    send_message.protocol[0] = MYFTP_PROTOCOL_MAGIC;
                    strcpy(send_message.protocol+1, MYFTP_PROTOCOL_NAME);
                    send_message.type = AUTH_REQUEST;
                    send_message.length = 12 + strlen(temp_login_id) + strlen(temp_login_pw) + 1;
                    snprintf(send_message.payload, 1024, "%s %s", temp_login_id, temp_login_pw);
                    
                    send(newSocket, &send_message, send_message.length, 0);

                    // Handle response
                    recv(newSocket, &recv_message, sizeof(struct message_s), 0);
                    if(recv_message.type == AUTH_REPLY && recv_message.status == 1) {
                        authenticated = 1;
                        // Store session key from payload
                        memcpy(session_key, recv_message.payload, 32);
                        printf("Authentication successful\n");
                    } else {
                        printf("Authentication failed\n");
                    }
                    break;
                }

                /*********************** 
                 * Handle ls command *
                 ***********************/
                case 3:
                    if( token = strtok_r(NULL," \n", &thread_safety), token != NULL ){
                            printf("Usage: ls (no argument is needed)\n");
                            continue;
                    }
                    /* Sending LIST_REQUEST */
                    send_message.protocol[0] = 0xe3;
                    strcat(send_message.protocol, "myftp");
                    send_message.type = 0xA5;
                    send_message.length = 12;
                    while ( send(newSocket, (char*)&send_message, send_message.length, 0) != 12 );

                    /* Attempt to receive LIST_REPLY */
                    recv(newSocket, (char *)&recv_message,sizeof(struct message_s), 0);
                    if( recv_type == 0xA6, recv_type != recv_message.type){
                        printf("Error: Client - Wrong header received, terminating connection");
                        exit(-1);
                    }
                    printf("----- file list start -----\n");
                    printf("%s", recv_message.payload);
                    printf("----- file list end -----\n");

                    
                    break;

                /*********************** 
                 * Handle get command *
                 ***********************/
                case 4:
                    token = strtok_r(NULL," \n", &thread_safety);
                    if( token == NULL ){
                        printf("Usage: get TARGET_FILENAME\n");
                        continue;
                    }
                    strcpy(target_filename, token);
                    token = strtok_r(NULL," \n", &thread_safety); 
                    if( token != NULL ){
                        printf("Usage: get TARGET_FILENAME\n");
                        continue;
                    }
                    printf("Downloading \"%s\"...\n",target_filename);

                    // Sending GET_REQUEST
                    send_message.protocol[0] = 0xe3;
                    strcat(send_message.protocol, "myftp");
                    send_message.type = 0xA7;
                    strcpy(send_message.payload, target_filename);
                    send_message.length = 12 + strlen(target_filename);
                    send(newSocket,(char *)(&send_message),send_message.length, 0);

                    // Receiving GET_REPLY
              
                    recv(newSocket,(char *)(&recv_message),sizeof(struct message_s)+1, 0);
                    // For debug
                    //printf("Showing GET_REPLY info\n");
                    //printf("protocol: %s\n", recv_message.protocol);
                    //printf("type: %x\n", (int)recv_message.type);
                    //printf("status: %d\n", (int)recv_message.status);
                    //printf("length: %d\n", recv_message.length);
                    //printf("payload: %s\n", recv_message.payload);
                    recv_type = 0xA8;
                    if (recv_message.type != GET_REPLY){
                        printf("Error: Client - Wrong header received, terminating connection");
                        exit(-1);
                    }
                    if (recv_message.status == 1){
                        fb = fopen(target_filename, "wb");
                        if (fb != NULL){
                            download_file(newSocket, fb);
                            printf("File downloaded.\n");
                            fclose(fb);
                        } else
                            printf("Error: Client - Cannot download file.\n");
                    } else {
                        printf("File does not exist.\n");
                    }
                    break;

                /*********************** 
                 * Handle put command *
                 ***********************/
                case 5:
                    token = strtok_r(NULL," \n", &thread_safety);
                    if( token == NULL ){
                        printf("Usage: put SOURCE_FILENAME\n");
                        continue;
                    }
                    strcpy(target_filename, token);
                    token = strtok_r(NULL," \n", &thread_safety);
                    if( token != NULL ){
                        printf("Usage: put SOURCE_FILENAME\n");
                        continue;
                    }
                    printf("Uploading \"%s\"...\n",target_filename);
                    
                    fb = fopen(target_filename, "rb");
                    if (fb != NULL){
                        printf("Sending PUT_REQUEST\n");
                        send_message.type = 0xA9;
                        send_message.protocol[0] = 0xe3;
                        strcat(send_message.protocol, "myftp");
                        memset(send_message.payload, '\0', 1024);
                        memcpy(send_message.payload, target_filename, strlen(target_filename));
                        send_message.length = 12 + strlen(target_filename);
                        send(newSocket,(char *)(&send_message),send_message.length, 0);
                        printf("PUT_REQUEST sent\n");

                        printf("Receiving PUT_REPLY\n");
                        memset(recv_message.payload, '\0', 1024);
                        recv(newSocket,(char *)(&recv_message),sizeof(struct message_s), 0);
                        if(recv_message.type == PUT_REPLY) {  // Was using assignment (=)
                            printf("PUT_REPLY received\n");
                        } else {
                            printf("Error: Invalid reply type\n");
                            exit(-1);
                        }
                        upload_file(newSocket, fb);
                        fclose(fb);
                        printf("File uploaded.\n");
                    }
                    else
                        printf("Error: Client - File does not exist.");

                    break;

                case 0:
                    /* otherwise */
                    printf("Error: Client - Bad Command\n");
                break;

            }

        } else {
            quit = 1;
        }
    }            


    // Cleanup
    send_quit_request(newSocket, &connected);
    if(newSocket != -1) close(newSocket);
    
    // OpenSSL cleanup
    EVP_cleanup();
    ERR_free_strings();
    
    printf("Client terminated\n");
    return 0;
}
