// Louisa Katlubeck
// Project 4
// Description: otp_dec  will connect to otp_dec_d and will ask it to decrypt ciphertext using a
// passed-in ciphertext and key. otp_dec should NOT be able to connect to otp_enc_d, even if it tries to connect on the correct port.
// By itself, otp_dec doesn’t do the decryption - otp_dec_d does. The syntax of otp_dec is: otp_dec ciphertext key port
// If otp_dec receives key or ciphertext files with ANY bad characters in them, or the key file is shorter than the ciphertext,
// then it should terminate, send appropriate error text to stderr, and set the exit value to 1.
// if otp_dec cannot connect to the otp_dec_d server, for any reason (including that it has accidentally tried to connect to the otp_enc_d server),
// it should report this error to stderr with the attempted port, and set the exit value to 2.
// Otherwise, upon successfully running and terminating, otp_dec should set the exit value to 0.
// Sources: https://www.cs.bu.edu/teaching/c/file-io/intro/, Beej's guide - http://beej.us/guide/bgnet/html/single/bgnet.html, http://www.cs.dartmouth.edu/~campbell/cs50/socketprogramming.html

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

void error(const char *msg) { perror(msg); exit(1); }                   // Error function used for reporting issues

int main(int argc, char *argv[])
{
	// Variable setup
	int socketFD, portNumber, charsWritten = 0, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
	char plainText[70001];
	char totalText[140005];
	FILE *fp;                           // file pointer
	char textFile[1000];                // text file name
	FILE *keyp;                         // key file pointer
	char keyFile[1000];                 // key file name
	int nextValue;					
	char nextChar;
	int i = 0;
	int sent = 0;                       // bytes sent to the server
	int bytesLeft;
	int textLength = 0;
	int keyLength = 0;
	char test[2];
	char t[2];

	// If there are not enough arguments
	if (argc < 4) { fprintf(stderr, "CLIENT: ERROR not enough arguments"); exit(2); }

	// Get the cipher text file and key file names
	strcpy(textFile, argv[1]);
	strcpy(keyFile, argv[2]);

	// Open and read the text file into text[]
	fp = fopen(textFile, "r");

	// If we could not open the text file
	if (fp == NULL) error("CLIENT: ERROR could not open plain text file\n");

	// If we could open the file, read in each character until we get to a terminating newline
	while ((nextValue = getc(fp)) != '\n') {
	// Check to make sure the input is valid
	if (!((nextValue >= 65 && nextValue <= 90) || nextValue == 32)) error("CLIENT: ERROR invalid character in the ciphertext\n");

	// Convert nextValue to a char and store in text[]
	nextChar = nextValue;
	//text[i] = nextChar;
	totalText[i] = nextChar;
	i++;
	textLength++;
	}

	// Add a newline to distinguish the end of the ciphertext
	totalText[i] = '\n';

	// increment i
	i++;

	// Close the text file
	fclose(fp);

	// open and read the key file into key[]
	keyp = fopen(keyFile, "r");

	// If we could not open the key file
	if (keyp == NULL) error("CLIENT: ERROR could not open the key file\n");

	// If we could open the file, read in each character until we get to a terminating newline
	while ((nextValue = getc(keyp)) != '\n') {
		// Check to make sure the input is valid
		if (!((nextValue >= 65 && nextValue <= 90) || nextValue == 32)) error("CLIENT: ERROR invalid character in the key\n");

		// Convert nextValue to a char and store in key[]
		nextChar = nextValue;
		//key[i] = nextChar;
		totalText[i] = nextChar;
		i++;
		keyLength++;
	}

	// Close the key file
	fclose(keyp);

	// Check to make sure the key length is not shorter than the plaintext length
	if (textLength > keyLength) {
		error("CLIENT: ERROR, key too short\n");
	}

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress));         // Clear out the address struct
	portNumber = atoi(argv[3]);                                         // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET;                                 // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber);                         // Store the port number
	//serverHostInfo = gethostbyname(argv[1]);                          // Convert the machine name into a special form of address
	serverHostInfo = gethostbyname("127.0.0.1");                        // Use localhost as the machine name; convert to a special form of address
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(2); }  // if opt_enc cannot connect to the server
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0);                         // Create the socket
	if (socketFD < 0) error("CLIENT: ERROR opening socket");

	// Connect to server, or print an error
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0)         // Connect socket to address
	{
	fprintf(stderr, "CLIENT: ERROR connecting on port %d\n", portNumber); exit(2);
	}

	// Make sure we are connected to otp_dec_d - send and receive "p" upon connection
	charsRead = recv(socketFD, test, sizeof(test), 0);
	fflush(stdout);
	if (charsRead < 0) error("CLIENT: ERROR reading from socket");

	t[0] = 'p';
	t[1] = '\0';

	charsWritten = send(socketFD, t, sizeof(t), 0);
	fflush(stdout);
	if (charsWritten < 0) error("ERROR writing to socket");            // Error output if send fails

	charsWritten = 0;

	// Print an error and exit status 2 if we are trying to connect to the wrong server
	if (strcmp(test, t))
	{
	fprintf(stderr, "CLIENT: ERROR otp_dec trying to connect to server other than otp_dec_d on port %d\n", portNumber); close(socketFD); exit(2);
	}

	// If we are successfully connected to otp_dec_d, proceed
	// Let the server know how large the message is
	// Get string length
	int str_size = strlen(totalText);
	// Send fixed-length data to pre-pend variable-length field with the latter's size
	send(socketFD, &str_size, sizeof(str_size), 0);

	// Send text to server - iterate until the entire text is sent
	size_t total = 0;
	ssize_t nb;

	while (total != strlen(totalText)) {
		nb = send(socketFD, totalText + total, strlen(totalText) - total, 0);
		if (nb == -1) error("CLIENT: ERROR, send failed");
		total += nb;
	}

	// Make sure all the text was sent
	if (nb < strlen(totalText)) error("CLIENT: WARNING: Not all key data written to socket!\n");
	
	// Get the plaintext from server
	// textLength + 1 to account for extra \n at end
	size_t receive = 0; 

	// Loop until we have received everything
	while (receive < textLength + 1) {
		ssize_t nb = recv(socketFD, plainText, textLength + 1, 0);
		// Check for errors and end of stream
		if (nb == -1) error("CLIENT: ERROR recv failed");
		if (nb == 0) break; 
		if (write(1, plainText, nb) == -1) error("CLIENT: ERROR file write failed");
		receive += nb;
	}

	// Return from the program
	exit(0);
}