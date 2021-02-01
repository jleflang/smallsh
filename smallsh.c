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
#include <sys/wait.h>
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
void handleTSTP(int signo) {

    char *messageFore = "Entering foreground-only mode (& is now ignored)\n";
    char *messageBack = "Exiting foreground-only mode\n";

    if (isBack) {
        // Write Out that we are entering Foreground-only
        // And set the flag to false
        write(1, messageFore, 49);
        fflush(stdout);
        isBack = false;

    } else {
        // Write Out that we are exiting Foreground-only
        // And set the flag to true
        write(1, messageBack, 49);
        fflush(stdout);
        isBack = true;

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
        procArr[0] = strdup("");
        return;
    }

    // Tokenize the input
    token = strtok(inArgs, " ");
    curs = 0;

    // Examine tokens for special chars and functions
    while (token != NULL) {

        // & -> Background process
        if (strcmp(token, "&") == 0) {
            *inBackmode = true;
        }
        // < -> Input Filename
        else if (strcmp(token, "<") == 0) {
            // Store the input file
            token = strtok(NULL, " ");
            strcpy(rFile, token);
        }
        // > -> Output Filename
        else if (strcmp(token, ">") == 0) {
            // Store the output file
            token = strtok(NULL, " ");
            strcpy(oFile, token);
        }
        // Command
        else {
            // Copy over the command
            procArr[curs] = strdup(token);

            // Go through the args for $$
            for (int j = 0; procArr[curs][j]; j++) {
                // If $$ is in the string, expand to shell_pid
                if ((procArr[curs][j] == '$') && 
                        (procArr[curs][j + 1] == '$')) {
                    // Replace
                    procArr[curs][j] = '\0';
                    snprintf(procArr[curs], 256, "%s%d", 
                            procArr[curs], shell_pid);
                }

            }

        }

        // Go to the next token
        curs++;
        token = strtok(NULL, " ");

    }

}

/**
 * printStatus subroutine
 * Prints the current status of the process
 *
 * Args:
 *  int childStatus: Status value of the child process
 *
 */
void printStatus(int childStatus) {

    if (WIFEXITED(childStatus)) {
        // We have an exit status
        printf("exit value %d\n", WEXITSTATUS(childStatus));

    } else {
        // we got a signal from the user
        printf("terminated by signal %d\n", WTERMSIG(childStatus));
    }
}

/**
 * execUserCMD subroutine
 * Executes a user command as a child process
 *
 * Args:
 *  char *input[]: Array of user command args
 *  bool *isBackground: Are we running in background
 *  int status: Process status
 *  struct sigaction sa: Process signal handler
 *  char *inFile: Input file
 *  char *outFile: Output file
 *
 */
void execUserCMD(char *input[], bool *isBackground, int status, 
        struct sigaction sa, char *inFile, char *outFile) {

    int openFD, writeFD, resultStat;
    pid_t childPid = -5;


    // Spawn the child
    childPid = fork();

    switch (childPid) {
        case -1:
            perror("Spawn Failed!\n");
            exit(1);

            break;

        case 0:
            // Take the handler, now hook ^C
            sa.sa_handler = SIG_DFL;
            sigaction(SIGINT, &sa, NULL);

            if (strcmp(inFile, "") == 0) {
                // Open the input file
                openFD = open(inFile, O_RDONLY);

                // Check the input file descriptor
                if (openFD == -1) {
                    perror("Unable to open input file\n");
                    exit(1);
                }

                // Copy the descriptor and assign
                resultStat = dup2(openFD, 0);

                if (resultStat == -1) {
                    perror("Unable to assign input file\n");
                    exit(2);
                }

                // Close
                fcntl(openFD, F_SETFD, FD_CLOEXEC);

            }

            if (strcmp(outFile, "") == 0) {
                // Open the output file
                writeFD = open(outFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);

                // Check the output file descriptor
                if (writeFD == -1) {
                    perror("Unable to open output file\n");
                    exit(1);
                }

                // Copy the descriptor and assign
                resultStat = dup2(writeFD, 1);

                if (resultStat == -1) {
                    perror("Unable to assign output file\n");
                    exit(2);
                }

                // Close
                fcntl(writeFD, F_SETFD, FD_CLOEXEC);
            }

            break;

        default:
            // Check for a background task and wait
            if (isBackground && isBack) {
                pid_t actPid = waitpid(childPid, &status, WNOHANG);
                printf("background pid is %d\n", childPid);
                fflush(stdout);
            } else {
                pid_t actPid = waitpid(childPid, &status, 0);
            }

            break;
    }

    while ((childPid = waitpid(-1, &status, WNOHANG)) > 0) {
        // Inform user when process is done
        printf("background pid %d is done: ", childPid);
        fflush(stdout);
        printStatus(status);
    }

}

int main(void) {

    int pid = getpid(), exitVal = 0;
    bool isExit = false, isBackgrounded = false, runLoop = true;
    char *inFile = NULL, *outFile = NULL, **input = NULL;
    // Signal structs
    struct sigaction small_sigint = {0}, small_sigtstp = {0};

    // Allocate the input buffer
    input = (char **)calloc(512, sizeof(char *));

    // Allocate the filename buffers
    inFile = (char *)calloc(256, sizeof(char));
    outFile = (char *)calloc(256, sizeof(char));

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
                chdir(getenv("HOME"));

            }
        }
        // Status commanded
        else if (strcmp("status", input[0])) {
            printStatus(exitVal);
        }
        // Execute user command
        else {
            execUserCMD(input, &isBackgrounded, exitVal, small_sigint, 
                    inFile, outFile);
        }

        // Reset the runtime vars
        isBackgrounded = false;
        inFile[0] = '\0';
        outFile[0] = '\0';

        for (int i = 0; i < 512; i++) {

            memset(input[i], '\0', strlen(input[i]));

        }

    }

    // Clean Up
    if (inFile != NULL) free(inFile);
    inFile = NULL;

    if (outFile != NULL) free(outFile);
    outFile = NULL;

    if (input != NULL) free(input);
    input = NULL;

    return EXIT_SUCCESS; 

}

