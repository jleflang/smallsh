/**
 * James Leflang
 * CS 344: Operating Systems I
 * Portfolio Project
 *
 * Description: This is an experimental shell that implements basic shell
 * functions that are native to Linux. This is not a complete shell as some
 * functions are not replicated from other shells such as bash, zcsh, etc.
 *
 * Licenced under BSD 2-Clause "Simplified"
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdbool.h>

#define MAX_LINE_LENGTH 2048

// Global flag for Backgrounding
// Unsafe but required!
bool isBack = true;

/**
 * handleTSTP subroutine
 * Handler for SIGTSTP to switch foreground/background modes.
 *
 * Args:
 *  int signo: Required for all handlers, unused
 *
 */
void handleTSTP(int sign) {

    char *messageFore = "Entering foreground-only mode (& is now ignored)\n";
    char *messageBack = "Exiting foreground-only mode\n";

    if (isBack) {
        // Write Out that we are entering Foreground-only
	// And set the flag to false
	write(1, messageFore, 49);
	fflush(stdout);
	&isBack = false;

    } else {
        // Write Out that we are exiting Foreground-only
	// And set the flag to true
	write(1, messageBack, 49);
	fflush(stdout);
	&isBack = true;

    }

}

/**
 * procInput subroutine
 * Process the user's input for our shell
 *
 * Args:
 *  int shell_pid: Shell's PID
 *  bool *inBackmode: Is backgrounding needed?
 *  char *rFile: Input files, if in args
 *  char *procArr: Processed input
 *  char *oFile: Output files, if in args
 *
 */
void procInput(const int shell_pid, bool *inBackmode, 
	       char *procArr[], char *rFile, char *oFile) {

   char inArgs[MAX_LINE_LENGTH], *token = NULL;
   int curs;

   // Prompt and wait for user input
   printf(": ");
   fflush(stdout);
   fgets(inArgs, MAX_LINE_LENGTH, stdin);

   // Trim newline
   // https://stackoverflow.com/questions/2693776/removing-trailing-newline-character-from-fgets-input
   // Nicer way
   inArgs[strcspn(inArgs, "\n")] = '\0';

   // User entered a blank
   if (strcmp(inArgs, "") == 0) {
       procArr = strdup("");
       return;
   }

   // Tokenize the input
   token = strtok(inArgs, " ");
   curs = 0;

   // Examine tokens for special chars and functions
   while (token != NULL) {
       
       // & -> Background process
       if (strcmp(token, "&") == 0) {
           inBackmode = true;
       }
       // < -> Input Filename
       else if (strcmp(token, "<") == 0) {
           // Store the input file
	   token = strtok(NULL, " ");
	   strcpy(rFile, token);
       }
       // > -> Output Filename
       else if (strcmp(token, ">") == 0) {
           //
	   token = strtok(NULL, " ");
	   strcpy(oFile, token);
       }
       // Command
       else {
           // Copy over the command
           procArgs[curs] = strdup(token);

	   //
	   for (int j = 0; procArgs[curs][j]; j++) {
               // If $$ is in the string, expand to shell_pid
	       if ((procArgs[curs][j] == '$') && 
	           (procArgs[curs][j + 1] == '$')) {
                   // Replace
		   procArgs[curs][j] = '\0';
		   snprintf(procArgs[curs], 256, "%s%d", 
		            procArgs[curs], shell_pid);
	       }

	   }

       }

       // Go to the next token
       curs++;
       token = strtok(NULL, " ");

   }

}

int main(void) {

    int pid = getpid();
    bool isExit = false, isBackgrounded = false, runLoop = true;
    char inFile[256] = '\0', outFile[256] = '\0';
    char *input[] = NULL;
    // Signal structs
    struct sigaction small_sigint = {0}, small_sigtstp = {0};

    // Allocate the input buffer
    input = (char *)calloc(512, sizeof(char));

    // Make the Signal Handlers
    small_sigint.sa_handler = SIG_IGN;
    sigfillset(&small_sigint.sa_mask);
    small_sigint.sa_flags = 0;
    sigaction(SIGINT, &small_sigint, NULL);

    small_sigtstp.sa_handler = handleTSTP;
    sigfillset(&small_sigtstp.sa_mask);
    small_sigtstp.sa_flags = 0;
    sigaction(SIGINT, &small_sigtstp, NULL);

    // Main Run Loop
    while (runLoop) {

       // Get and process stdin
       procInput(pid, &isBackgrounded, input, inFile, outFile);

       // Ignore comments and blanks
       if ((strncmp(input[0], "#", 0) == 0) || (input[0][0] = '\0')) {
           continue;
       }
       // Exit commanded
       else if (strcmp("exit", input[0]) == 0) {
           runLoop = false;
       }
       // Change Directory "cd" commanded
       else if (strcmp("exit", input[0]) == 0) {
           // User specified a dir
	   if (input[1] != NULL) {
               if (chdir(input[1]) == -1) {
                   printf("No directory found named %s", input[1]);
		   fflush(stdout);
	       }
	   } else {
	       // Go to HOME
	       chrdir(getenv("HOME"));

	   }
       }

    }

    return EXIT_SUCCESS; 

}

