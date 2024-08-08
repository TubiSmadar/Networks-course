/* TCP Server */

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
#include <time.h>
#include <sys/time.h>

/* Macros */
#define SERVER_PORT 1604
#define FILESIZE 2097166

/* Methods */
long recvMsg(int socket, char *buffer);

/* Global Variables */
int authentication = 11973;
char buffer[FILESIZE/2];
char ccAlgorithm[8] = {0};

int main(){

	// Arrays and values for calculating receival times
	long recvTimes1[1000] = {-1};
	long avg1 = 0;
	long recvTimes2[1000] = {-1};
	long avg2 = 0;
	int recvTimesIndex = 0;

	// Create socket for receiving files. This socket acts as a TCP server socket.
	int receiverSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (receiverSocket == -1){
		printf("Socket not created: %d", errno);
	}
	
	// If the socket is closed, wait 30-120 seconds before final removal in case of reuse.
	int enableReuse = 1;
	if (setsockopt(receiverSocket, SOL_SOCKET, SO_REUSEADDR, &enableReuse, sizeof(int)) < 0) {
		printf("setsockopt() failed with error code : %d", errno);
	}

	// Create internet socket-address object, named serverAddress. Will accept connections from all IPs.
	struct sockaddr_in serverAddress;
	memset(&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = INADDR_ANY;
	serverAddress.sin_port = htons(SERVER_PORT);
	
	// Bind the socket to the Receiver's given internet address.
	int bindStatus = bind(receiverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress));
	if (bindStatus == -1){
		printf("Bind failed with error code : %d" , errno);
		close(receiverSocket);
		return -1;
	}
	printf("Bind was successful\n");
	
	// Put socket in listening mode, waiting for connections.
	int listenStatus = listen(receiverSocket, 5);
	if (listenStatus == -1){
		printf("Listen failed with error code : %d" , errno);
		close(receiverSocket);
		return -1;
	}
	printf("Receiver listening and ready for connections\n");

	// Create internet socket-address object, named clientAddress, for connections made with Receiver.
	struct sockaddr_in clientAddress;
	socklen_t clientAddressLen = sizeof(clientAddress);
	memset(&clientAddress, 0, clientAddressLen);

	// Accept a connection from a client
	int clientSocket = accept(receiverSocket, (struct sockaddr *)&clientAddress, &clientAddressLen);
	if (clientSocket == -1) {
		printf("listen failed with error code : %d" ,errno);
		close(clientSocket);
		return -1;
    }
    printf("A new client connection has been accepted.\n");

    // Flag used for exiting while loop
    int flag = 1;
    long bytesReceived = 0;
    // Receive files from Sender, until error of exit code is received
    while (flag) {

		struct timeval start, stop;
		
		// Receive first half of the file, measure receival times
        printf("The CC algorithm now being used is: Cubic\n");
		gettimeofday(&start, NULL);
		bytesReceived = recvMsg(clientSocket, buffer);
		gettimeofday(&stop, NULL);
        if (bytesReceived == -1) {
        	break;
        } else {
        	printf("Received message: %ld bytes.\n", bytesReceived);
        }
		long receivalTime = ((stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec);
		recvTimes1[recvTimesIndex] = receivalTime;
		avg1 += receivalTime;

		// Send authentication
		int authenticationStatus = send(clientSocket, &authentication, sizeof(int), 0);
		if (authenticationStatus != 4) {
			printf("Authentication failed.\n");
		}

		// Change CC algorithm
		strcpy(ccAlgorithm, "reno");
        int changeCC = setsockopt(clientSocket, IPPROTO_TCP, TCP_CONGESTION, ccAlgorithm, sizeof(ccAlgorithm));
        if(changeCC != 0) {
            printf("CC algorithm changing has failed");
            break;
        }
        printf("The CC algorithm now being used is: Reno\n");

        // Receive second half of the file, measure receival times
		gettimeofday(&start, NULL);
		bytesReceived = recvMsg(clientSocket, buffer);
		gettimeofday(&stop, NULL);
        if (bytesReceived == -1) {
        	break;
        } else {
        	printf("Received message: %ld bytes.\n", bytesReceived);
        }
		receivalTime = ((stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec);
		recvTimes2[recvTimesIndex++] = receivalTime;
		avg2 += receivalTime;

		// Receive user decision - exit program or resend the file.
		int userDecision;
		recv(clientSocket, &userDecision, 1, 0);
		if (userDecision == 0) {
	 		printf("Exit code received, goodbye.\n");
        	flag = 0;
        } else if (userDecision == 1) {
        	printf("User has decided to resend the file.\n");
        	//Change back the CC algorithm
   			strcpy(ccAlgorithm, "cubic");
  			changeCC = setsockopt(clientSocket, IPPROTO_TCP, TCP_CONGESTION, ccAlgorithm, sizeof(ccAlgorithm));
        	if(changeCC != 0) {
            	printf("CC algorithm changing has failed");
            	exit(1);
        	}
        } else {
        	printf("Didn't receive a valid decision from user, exiting program.\n");
        	flag = 0;
        }
    }

    // End program

    // Close clientSocket connection
    close(clientSocket);

    // Print out receival times for file parts
    for (int i = 1; i <= recvTimesIndex; i++){
    	printf("Send number %d took:\n", i);
    	printf("%ld microseconds for first half.\n", recvTimes1[i-1]);
    	printf("%ld microseconds for second half.\n", recvTimes2[i-1]);
    }

    // Print out the average receival time for each part of the file
    avg1 = (avg1/recvTimesIndex);
    avg2 = (avg2/recvTimesIndex);
    printf("Average receival time for the first half of the file is: %ld microseconds.\n",avg1);
    printf("Average receival time for the second half of the file is: %ld microseconds.\n",avg2);

    // Print out the average receival time for a file
    long totalAvg = ((avg1+avg2)/2);
    printf("Average receival time for the entire file is: %ld microseconds.\n", totalAvg);

    // Close the receiverSocket
    close(receiverSocket);
    return 0;
}

long recvMsg(int socket, char *buffer) {
    bzero(buffer, FILESIZE/2);
    long bytesReceived = 0;
    while(bytesReceived < FILESIZE/2){
    	bytesReceived += recv(socket, buffer, FILESIZE/2, 0);
    	if (bytesReceived <= 0) {
	 		printf("Error in receiving file.\n");
	 		break;
	 	}
	}
	return (bytesReceived <= 0 ? -1 : bytesReceived);
}