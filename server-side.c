// gcc sampleServer.c -o sampleServer -lpthread

#include "myftp.h"
#include<signal.h>
#include<pthread.h>


struct message_s{
    char protocol[6];
    char type;      /* type (1 byte) */
    char status;        /* status (1 byte) */
    int length;     /* length (header + payload) (4 bytes) */
    char payload[1024]; /* payload */
} __attribute__ ((packed));

int send_open_conn_reply(int newSocket){
	struct message_s reply_message;

	reply_message.protocol[0] = 0xe3;
	strcat(reply_message.protocol, "myftp");
	reply_message.type = 0xA2;
	reply_message.status = 1;
	reply_message.length = 12;

	send(newSocket, (char*)(&reply_message),reply_message.length, 0);
	return 0;
}

int check_auth(char loginInfo[1024]){
	FILE *fp;
	char usrnameAndPw[1024];

	if(fp = fopen("access.txt","rb"), fp == NULL)
		return 0;
	else{
		while( fgets(usrnameAndPw, 1024, fp) != NULL ){
			usrnameAndPw[strlen(usrnameAndPw)-1] = '\0';
			printf("login info: %s\n", loginInfo);
			printf("login info length: %d\n", (int)strlen(loginInfo));
			printf("cmp info: %s\n", usrnameAndPw);
			printf("cmp info length: %d\n", (int)strlen(usrnameAndPw));
			printf("cmp result: %d\n", strcmp(loginInfo, usrnameAndPw));
			if( strcmp(loginInfo, usrnameAndPw) == 0 )
				// login info verified
				return 1;
		}
	}
	return 0;
}

int send_auth_reply(int newSocket, int status){
	struct message_s reply_message;
	reply_message.protocol[0] = 0xe3;
	strcat(reply_message.protocol, "myftp");
	reply_message.type = 0xA4;
	reply_message.status = status;
	reply_message.length = 12;
	send(newSocket, (char*)(&reply_message),reply_message.length, 0);
	return 0;
}

int list_dir_send_list_reply(int newSocket){
	DIR *dir;
	struct dirent dp;
	struct dirent *ls_thread_safety;
	struct message_s reply_message;
	int return_code;

	
	memset(reply_message.payload, '\0', 1024);
	printf("printing dir1: %s\n", reply_message.payload);
	reply_message.protocol[0] = 0xe3;
	strcat(reply_message.protocol, "myftp");
	printf("size of protocol: %d\n", (int)sizeof(reply_message.protocol));
	reply_message.type = 0xA6;
	printf("printing dir2: %s\n", reply_message.payload);
	/* Read and Store the Directory Entries into the payload then send it out */
        memset(reply_message.payload, '\0', 1024);
	dir = opendir("./filedir");
	if ( dir == NULL){
		printf("Error: Server - failed to open file directory");
		reply_message.length = 12 + strlen(reply_message.payload);
		while( send(newSocket, (char*)(&reply_message),reply_message.length, 0) != reply_message.length );
	} else {
		printf("printing dir3: %s\n", reply_message.payload);
		for ( return_code=readdir_r(dir, &dp, &ls_thread_safety);
			ls_thread_safety!=NULL && return_code==0;
			return_code=readdir_r(dir, &dp, &ls_thread_safety)) {
			if( dp.d_type != 4 ) {
				strcat(reply_message.payload, dp.d_name);
				strcat(reply_message.payload, "\n");
				printf("printing dir4: %s\n", reply_message.payload);
			}
		}	

		// send LIST_REPLY
		reply_message.length = 12 + strlen(reply_message.payload);
		while( send(newSocket, (char*)(&reply_message),reply_message.length, 0) != reply_message.length );
	
		closedir(dir);
	}

	return 0;
}

int send_get_reply(int newSocket, int status){
	struct message_s reply_message;
	char temp_type = 0xA8;

	memset(reply_message.payload, '\0', 1024);
	reply_message.protocol[0] = 0xe3;
	strcat(reply_message.protocol, "myftp");
	reply_message.type = temp_type;
	reply_message.status = status;
	reply_message.length = 12;

	send(newSocket, (char *)(&reply_message), reply_message.length, 0);
	return 0;
}

int sendn(int newSocket, const void* buf, int buf_len)
{
    int n_left = buf_len;         // actual data bytes sent
    int n;
    while (n_left > 0){
        if ((n = send(newSocket, buf + (buf_len - n_left), n_left, 0)) < 0){
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

int send_file_data(int newSocket, FILE * fb){
	struct message_s data_message;
    int size;

	memset(data_message.payload, '\0', 1024);
	data_message.protocol[0] = 0xe3;
	strcat(data_message.protocol, "myftp");
	data_message.type = 0xFF;
	data_message.status = 1;
        fseek(fb, SEEK_SET, 0);
    do{
	    size = fread(data_message.payload, 1, 1024, fb);
		data_message.length = 12 + size;
                     
        if (size < 1024){
			data_message.status = 0;              
	}
        if (sendn(newSocket, (char *)&data_message, sizeof(struct message_s)) == -1){
			printf("Error: Server - Failed to send file\n");
			exit(-1);
		}
	} while( data_message.status != 0 );

	return 0;
}


int recvn(int newSocket, void* buf, int buf_len){
    int n_left = buf_len;
    int n = 0;
    while (n_left > 0){
        if ((n = recv(newSocket, buf + (buf_len - n_left), n_left, 0)) < 0){
            if (errno == EINTR)
                n = 0;
            else
                return -1;
        } else if (n == 0){
            return 0;
        }
        n_left -= n;
    }
    return buf_len;
}

int recv_file_data(int newSocket, char directory[]){
	struct message_s data_message;
	FILE * fb;
	char correct_type = 0xFF;
	fb = fopen(directory, "wb");
	if (fb != NULL){
		do {
			if (recvn(newSocket, (char *)&data_message, sizeof(struct message_s)) == -1){
				printf("failed to receive.\n");
				exit(-1);
			}
			if (data_message.type != correct_type){
				printf("Error: Server - Incorreft type\n");
				exit(-1);
			}

			fwrite(data_message.payload, 1, data_message.length-12, fb);

		} while ( data_message.status != 0 );
		fclose(fb);
	}
	else{
		printf("Cannot write file.\n");
		exit(-1);
	}
	return 0;
}

/*
 * This will handle connection for each client
 * */
void *client_handler(void *socketDescriptor){
    // Get the socket descriptor
    int newSocket = *(int*) socketDescriptor;
    int readSize;
    char *message, *realMessage, clientMessage[2000];
    int quit;
    struct message_s recv_message, send_message;
    int connected, authenticated;

    FILE *fb;
	char target_filename[1024];
	char directory[1024 + 10];

    authenticated = 0;
    connected = 0;
    quit = 0;

    while (quit == 0){
	    // Get message from client
	    memset(recv_message.payload, '\0', 1024);
		readSize = recv(newSocket, (char *)&recv_message, sizeof(struct message_s), 0);
		// Print type, for debugging
		printf("recv_message.type is %x\n", recv_message.type);
		// Analyze message
	    switch( recv_message.type ){
	    	/********************************
	    	 *	Handle OPEN_CONN_REQUEST	*
	    	 ********************************/
			case (char) 0xA1:
				printf("Server - OPEN_CONN_REQUEST received\n");
				send_open_conn_reply(newSocket);
				printf("Server - OPEN_CONN_REPLY sent\n");
				connected = 1;
			break;

			/********************************
	    	 *	Handle AUTH_REQUEST	*
	    	 ********************************/
			case (char) 0xA3:
				printf("Server - AUTH_REQUEST received\n");
				recv_message.payload[recv_message.length-5] = '\0';
				printf("Server - Authenticating: %s\n",recv_message.payload);
				authenticated = check_auth(recv_message.payload);
				send_auth_reply(newSocket, check_auth(recv_message.payload));
				printf("Server - AUTH_REPLY sent\n");

				if( authenticated == 1)
					printf("\t(Server - Access Granted)\n");
				else
					printf("\t(Server - Access Failed)\n");

			break; 

			/********************************
	    	 *	Handle LIST_REQUEST	*
	    	 ********************************/
			case (char) 0xA5:
				printf("Server - LIST_REQUEST received\n");
				if (authenticated) {
					list_dir_send_list_reply(newSocket);
					printf("Server - LIST_REPLY sent\n");
				} else {
					strcpy(send_message.payload, "Server - You are not authenticated!\n");
					send_message.length = 12 + strlen(send_message.payload);
					while( send(newSocket, (char*)(&send_message),send_message.length, 0) != send_message.length );
				}
				

				
			break;

			/********************************
	    	 *	Handle GET_REQUEST	*
	    	 ********************************/
			case (char) 0xA7:
				if (authenticated) {
					strncpy(target_filename, recv_message.payload,recv_message.length-12);
					target_filename[recv_message.length-12] = '\0';

					printf("target filename: %s\n", target_filename);
					printf("GET_REQUEST: %s\n", recv_message.payload);

					strcpy(directory, "./filedir/");
					strcat(directory, target_filename);
					if(fb = fopen(directory, "rb"), fb != NULL){
						printf("Server - File found.\n");
                                    printf("directory: %s\n", directory);
                                      
						send_get_reply(newSocket, 1);
						printf("GET_REPLY Sent!\n");
                                       
              					sleep(1);

						send_file_data(newSocket, fb);
							
						fclose(fb);
                                                
					} else {
						printf("Error: Server - File does not exist.\n");
						send_get_reply(newSocket, 0);
						printf("GET_REPLY Sent\n");
					}
				} else {
					strcpy(send_message.payload, "Server - You are not authenticated!\n");
					send_message.length = 12 + strlen(send_message.payload);
					while( send(newSocket, (char*)(&send_message),send_message.length, 0) != send_message.length );
				}
			break;

			/********************************
	    	 *	Handle PUT_REQUEST	*
	    	 ********************************/
			case (char) 0xA9:
				if (authenticated){
					strncpy(target_filename, recv_message.payload,recv_message.length-12);
					target_filename[recv_message.length-12] = '\0';
					printf("target filename: %s\n", target_filename);
					printf("PUT_REQUEST: %s\n", recv_message.payload);

					printf("PUT_REQUEST Received\n");
					strcpy(directory, "./filedir/");
					strcat(directory, target_filename);
					memset(send_message.payload, '\0', 1024);
					send_message.protocol[0] = 0xe3;
					strcat(send_message.protocol, "myftp");
					send_message.type = 0xAA;
					send_message.length = 12;
					send(newSocket, (char*)(&send_message), send_message.length, 0);
					printf("PUT_REPLY Sent\n");
					recv_file_data(newSocket, directory);
				} else {
					strcpy(send_message.payload, "Server - You are not authenticated!\n");
					send_message.length = 12 + strlen(send_message.payload);
					while( send(newSocket, (char*)(&send_message),send_message.length, 0) != send_message.length );
				}
			break;

			/********************************
	    	 *	Handle QUIT_REQUEST	*
	    	 ********************************/
			case (char) 0xAB:
				printf("Disconnecting by request. (socket: %d)\n", newSocket);

				send_message.protocol[0] = 0xe3;
				strcat(send_message.protocol, "myftp");
				send_message.type = 0xAC;
				send_message.length = 12;
				while( send(newSocket, (char*)(&send_message),send_message.length, 0) !=12 );
				close(newSocket);
				quit = 1;
			break;

			/* Invalid Protocol */
			default: 
				printf("Error: Server - Invalid Protocol Received");
				quit = 1;
			break;
	    }
	}

    

    puts("Client disconnected");
    fflush(stdout);

    // Free the socket pointer
    free(socketDescriptor);
    printf("ending thread\n");
    pthread_exit(NULL);
    

    
}


// Global variables
int serverPortNumber = 0;
int socketDescriptor = -1;
struct sockaddr_in serverAddr,clientAddr;
char one;


int main(int argc, char* argv[]){

	int newSocket, c;
	pthread_t clientThread;
	char *message;
	int *pNewSocket;
	DIR *dir;

	if( argc != 2 )
		printf("\n\tUsage: %s [PORT_NUMBER]\n\n", argv[0]);
	else{

		if( serverPortNumber = atoi(argv[1]), serverPortNumber!=-1 && serverPortNumber>0 )
			printf("\n# Server Started: Awaiting connections from Port %d #\n\n", serverPortNumber);
		else{
			printf("\n\tError: Port number is out-of-range\n\n");
			exit(-1);
		}

		if (dir = opendir("./filedir"), dir == NULL){
			printf("Error: ./filedir not accessable");
			exit(-1);
		} else {
			closedir(dir);
		}

		//serverPortNumber = 8888;
		printf("\n# Server Started: Awaiting connections from Port %d #\n\n", serverPortNumber);

		// 1. Create a socket 
	    socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
		if ( socketDescriptor == -1){
			printf("Error: Server - Failed to create a socket\n");
			exit(-1);
		} else {
			printf("Server - Socket created %d \n", socketDescriptor);		
		}

		// 2. Binding
		setsockopt(socketDescriptor, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
		serverAddr.sin_port = htons(serverPortNumber);
		if (bind(socketDescriptor, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < -1) {
			printf("\n\tError: Failed to bind\n\n");
			exit(-1);
		} else {
			printf("Server - Binding succeeded\n");
		}

		// 3. Put server in listening mode
		if (listen(socketDescriptor, 3) == -1){
			printf("Error: Server - Failed to be put in listening mode");
			exit(-1);
		} else {
			printf("Server - Listening\n");
		}

		// 4. Accept connections
		c = sizeof(struct sockaddr_in);
		while (1){
			newSocket = -1;
			newSocket = accept(socketDescriptor, (struct sockaddr *)&clientAddr, (socklen_t*)&c);

			if( newSocket <= 0 ){
				printf("Error: Server - accept() failed\n");
				//server_shutdown();
			} else {
				printf("Server - Connection Established (IP: \"%s\" at port %u)\n", inet_ntoa(clientAddr.sin_addr), clientAddr.sin_port);
			}

			 pNewSocket = (int*) malloc(1);
	        *pNewSocket = newSocket;

			if (pthread_create( &clientThread, NULL, client_handler, (void*) pNewSocket) < 0){
				printf("Error: Server - Could not create thread\n");
			}
			pthread_detach(clientThread);
		}
	}
}



