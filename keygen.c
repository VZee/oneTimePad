// Louisa Katlubeck
// CS 344 
// Keygen creates a file of a user-specified key length. The characters are any of the 27 allowed
// characters (all capital letters and the space), using the UNIX rand() randomization. After outputting the 
// user-specified length, the program outputs a final newline character.
// Any errors are output to stderr. 
// The format for the program is: keygen keylength

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[])
{
    //////////////////////////////////////////////////////////////////////
    // variable setup 
    int keyLength = atoi(argv[1]);      
    //char characterPool[28] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ \0"; // pool of characters to pick from for the key
	char characterPool[27] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

    //////////////////////////////////////////////////////////////////////
    // error handling
    // if there are not two arguments (the program name and a length) output an error
    if (argc != 2){
        fprintf(stderr, "Incorrect number of arguments\n"); 
        exit(0); 
    }

    //////////////////////////////////////////////////////////////////////
    // if the key length is valid, proceed to generate a key of that length
    // seed the random generator
    srand((unsigned int)time(0));
    int i = 0;

    // generate and output the key
    // get a random number from 0 to 26 to use to select the next character from characterPool
    // then print that character
    for (i = 0; i < keyLength; i++){
        int next = rand()%27;    
        printf("%c", characterPool[next]);
    }

    // print the final newline character
    printf("\n");

    // return
    return 0;
}