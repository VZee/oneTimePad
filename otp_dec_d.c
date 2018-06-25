// Louisa Katlubeck
// Project 4
// Description: otp_dec_d will decrypt ciphertext it is given, using the passed-in ciphertext and key. Thus, it returns plaintext again to otp_dec.
//  Upon execution, otp_dec_d must output an error if it cannot be run due to a network error, such as the ports being unavailable. 
// Its function is to perform the actual decoding. This program will listen on a particular port/socket, 
// assigned when it is first ran. The syntax for otp_dec_d is: otp_dec_d listening_port. 
// When a connection is made, otp_dec_d must call accept() to generate the socket used for actual communication, 
// and then use a separate process to handle the rest of the transaction, which will occur on the newly accepted socket.
// This child process of otp_dec_d must first check to make sure it is communicating with otp_dec. After verifying 
// that the connection to otp_dec_d is coming from otp_dec, then this child receives from otp_dec ciphertext and a 
// key via the communication socket (not the original listen socket). The otp_dec_d child will then write back the 
// plaintext to the otp_dec process that it is connected to via the same communication socket. Note that the key 
// passed in must be at least as big as the ciphertext. Your version of otp_dec_d must support up to five concurrent socket 
// connections running at the same time. Again, only in the child process will the actual decryption take place, and the 
// plaintext be written back: the original server daemon process continues listening for new connections.
// Sources: http://beej.us/guide/bgnet/, https://stackoverflow.com/questions/3217629/how-do-i-find-the-index-of-a-character-within-a-string-in-c,
// how to fork - http://clinuxcode.blogspot.com/2014/02/concurrent-server-handling-multiple.html, https://stackoverflow.com/questions/13669474/multiclient-server-using-fork,
// http://www.facweb.iitkgp.ernet.in/~agupta/netlab/server_TCP_Conc.c, http://www.cs.dartmouth.edu/~campbell/cs50/socketprogramming.html

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

void error(const char *msg) { perror(msg); exit(1); }                       // Error function used for reporting issues

int main(int argc, char *argv[])
{
	// Variable setup
	int listenSocketFD, establishedConnectionFD, portNumber, charsRead = 0, charsWritten = 0;
	socklen_t sizeOfClientInfo;
	struct sockaddr_in serverAddress, clientAddress;
	int i = 0;
	char *newLine;
	int newLineIndex;
	char nextChar;
	int nextValue;
	char characterPool[28] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ \0"; // pool of characters to pick from for the key
	int sent = 0;
	int bytesLeft;
	char test[2];
	char t[2];
	char *tp;
	char *kp;
	int textIndex;
	int keyIndex;
	int pid;

	// If there are not enough arguments
	if (argc < 2) { fprintf(stderr, "USAGE: %s port\n", argv[0]); exit(1); }

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress));        // Clear out the address struct
	portNumber = atoi(argv[1]);                                         // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET;                                 // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber);                         // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY;                         // Automatically fill with my IP

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0);                   // Create the socket
	if (listenSocketFD < 0) error("ERROR opening socket");

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
	error("ERROR on binding");
	listen(listenSocketFD, 5);                                          // Flip the socket on - it can now receive up to 5 connections

    // Keep the server open
	while (1) {
		// Accept a connection, blocking if one is not available until one connects
		sizeOfClientInfo = sizeof(clientAddress);                           // Get the size of the address for the client that will connect
		establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
		if (establishedConnectionFD < 0) error("ERROR on accept");

		// Make sure we are communicating with otp_dec - will send and receive 'p'
		test[0] = 'p';
		test[1] = '\0';
		charsWritten = send(establishedConnectionFD, test, sizeof(test), 0);
		fflush(stdout);
		if (charsWritten < 0) error("SERVER: ERROR writing to socket");            // Error output if send fails

		charsRead = recv(establishedConnectionFD, t, sizeof(t), 0);
		if (charsRead < 0) error("SERVER: ERROR reading from socket");            // Error output if read fails

		// If we are connected to otp_dec, proceed
		if (!(strcmp(test, t))) {
			// Fork a child process
			pid = fork();

			// If the fork worked and we are in the child
			if (pid == 0) {
				// Get how big the message is
				// Local variable creation for reading the message
				int fileSize = 0, read = 0, recvThatRead = 0;
				recv(establishedConnectionFD, &fileSize, sizeof(fileSize), 0);

				// Create a temp file that is the size of the incoming message
				char temp[fileSize];

				// Loop while what we have read so far is less than the file size
				while (read != fileSize)
				{
					recvThatRead = recv(establishedConnectionFD, temp + read, fileSize - read, 0);
					if (recvThatRead < 0)
					{
						// If there is an error reading from the socket handle the error and break out of the while loop
						error("SERVER: ERROR reading from socket");
						break;
					}
					read += recvThatRead;
				}

				// Reset charsRead
				charsRead = 0;

				// Find the newline separater index
				newLine = strchr(temp, '\n');
				newLineIndex = abs(temp - newLine);

				char plaintext[newLineIndex + 1];

				// Decrypt the plaintext received opt_dec
				for (i = 0; i < newLineIndex; i++) {
					// Get the characters from the plaintext and the corresponding location in the key (found by adding i + newLineIndex + 1)
					char textTemp = temp[i];
					char keyTemp = temp[i + newLineIndex + 1];

					// Find the indices of those letters in the character pool and subtract
					tp = strchr(characterPool, textTemp);
					kp = strchr(characterPool, keyTemp);

					textIndex = abs(characterPool - tp);
					keyIndex = abs(characterPool - kp);
					nextValue = textIndex - keyIndex;

					// Do mod(27) on the resulting sum, accounting for 26 alphabetical characters and the space
					// If the result is greater than 26, then the result is the remainder after subtracting 27 (ie if go past space, restart at A)
					if (nextValue < 0) nextValue = nextValue + 27;
					nextValue = nextValue % 27;

					//if(nextValue < 0) nextValue = nextValue + 27;
					char nextChar = characterPool[nextValue];

					// Copy that result to ciphertext
					plaintext[i] = nextChar;
				}

				// Add the '\n'
				plaintext[i] = '\n';

				// Send text to client - iterate until all of the text is sent
				size_t total = 0;
				ssize_t nb;

				while (total < strlen(plaintext)) {
					nb = send(establishedConnectionFD, plaintext + total, strlen(plaintext) - total, 0);
					if (nb == -1) error("SERVER: ERROR, send failed");
					else if (nb == 0) break;
					total += nb;
				}
				// Close the existing child socket which is connected to the client and reset variables
				close(establishedConnectionFD);                                 
				charsWritten = 0;
				bytesLeft = 0;
			}

			// Else if we are in the parent, make sure the child socket is closed
			else {
				close(establishedConnectionFD);
			}
		}
	}

	// Don't do this since we want the connection to remain open
	//close(listenSocketFD);                                          // Close the listening socket

	// Return from the program
	return 0;
}