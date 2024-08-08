/* TCP Client */

/* Included Libraries */
#include <stdio.h>
#include <stdlib.h> 
#include <errno.h> 
#include <string.h> 
#include <sys/types.h> 
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

/* Macros */
#define SERVER_PORT 1604
#define SERVER_IP "127.0.0.1"
#define FILESIZE 2097166

/* Methods */
void sendMsg(int socket, char* fileText, int length);
int authenticate(int socket);

/* Global Variables */
char *fileName = "Ex3_file.txt";
char fileText[FILESIZE];
int authentication = 11973;
char buffer[FILESIZE/2];
char ccAlgorithm[8] = {0};


int main(){

    // Save file content as the fileText array. Close file when done copying.
    printf("Reading file...\n");
    FILE *fp;
    fp = fopen(fileName, "r");
    if (fp == NULL) {
        printf("File reading failed.\n");
        return -1;
    }
    fread(fileText, 1, FILESIZE, fp);
    fclose(fp);
    printf("File closed.\n");

    // Create socket for sending files to Receiver. This socket acts as a TCP client socket.
    int senderSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (senderSocket == -1){
        printf("Socket not created: %d\n", errno);
    }

    // Create internet socket-address object, named serverAddress.
    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(SERVER_PORT);
    int ip_addr = inet_pton(AF_INET, (const char *)SERVER_IP, &serverAddress.sin_addr);
    if (ip_addr < 1){
        ip_addr == -1 ? printf("inet_pton() failed %d: ", errno) : printf("inet_pton() src invalid");
    }

    // Connect senderSocket to Receiver's (server) internet address.
    int connectionStatus = connect(senderSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress));
    if (connectionStatus == -1){
        printf("Socket not connected: %d", errno);
    } else {
        printf("Connected to Receiver succesfully\n");
    }

    while(1) {
        
        printf("The CC algorithm now being used is: Cubic\n");

        // Send first half of file
        sendMsg(senderSocket, fileText, FILESIZE/2);

        // Check for authentication with Receiver
        int authenticationStatus = authenticate(senderSocket);
        if (authenticationStatus == -1) {
            printf("Authentication wasn't correct.\n");
            break;
        }
        printf("Authentication was correct.\nChanging CC algorithm and sending part 2 of the file.\n");

        // Change CC algorithm
        strcpy(ccAlgorithm, "reno");
        int changeCC = setsockopt(senderSocket, IPPROTO_TCP, TCP_CONGESTION, ccAlgorithm, sizeof(ccAlgorithm));
        if(changeCC == 0) {
            printf("The CC algorithm now being used is: Reno\n");
        } else {
            printf("CC algorithm changing has failed");
            break;
        }

        // Send second half of file
        sendMsg(senderSocket, fileText+FILESIZE/2, FILESIZE/2);

        // User decision - resend the file or exit the program.
        int decision;
        printf("Would you like to send the file again or exit program?\n0: Exit\n1: Send again\n");
        scanf("%d", &decision);

        if (decision == 1){
            send(senderSocket, &decision, 1, 0);
            printf("Changing CC algorithm.\n");
            strcpy(ccAlgorithm, "cubic");
            changeCC = setsockopt(senderSocket, IPPROTO_TCP, TCP_CONGESTION, ccAlgorithm, sizeof(ccAlgorithm));
            if(changeCC != 0) {
                printf("CC algorithm changing has failed.\n");
                exit(1);
            }
        } else if (decision != 1) {
            send(senderSocket, &decision, 1, 0);
            sleep(1);
            break;
        }
    }

    // Close senderSocket and exit program
    close(senderSocket);
    printf("Socket closed.\nExiting program.\n");
    return 0;
}


void sendMsg(int socket, char* fileText, int length) {
    int bytesSent = send(socket, fileText, length, 0);
    if (bytesSent == -1) {
        printf("Message failed to send, with error code : %d" ,errno);
    } else if (bytesSent == 0) {
        printf("TCP connection was closed by Receiver prior to send().\n");
    } else if (bytesSent < (FILESIZE/2)) {
        printf("Sent only %d bytes of the required %d.\n", bytesSent, (FILESIZE / 2));
    } else {
        printf("Message was successfully sent.\n");
    }
}

int authenticate(int socket) {
    int receivedAuthentication = 0;
    recv(socket, &receivedAuthentication, sizeof(int), 0);
    return(receivedAuthentication == authentication ? 1 : -1);
}