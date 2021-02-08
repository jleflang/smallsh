/**
 * James Leflang
 * CS 344: Operating Systems I
 * Portfolio Project
 *
 * Description: This is an experimental shell that implements basic shell
 * functions that are native to Linux. This is not a complete shell as some
 * functions are not replicated from other shells such as bash, zcsh, etc.
 *
 * Licenced under BSD 2-Clause "Simplified" License
 *
 */
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdbool.h>
#include <limits.h>

#define MAX_ARGS        512
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

    static char *messageFore = 
                "Entering foreground-only mode (& is now ignored)\n";
    static char *messageBack = "Exiting foreground-only mode\n";

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
 * Process the user's input for our shell into an array of args, 
 * and separate file names into separate pointers.
 *
 * Args:
 *  int shell_pid: Shell's PID
 *  bool *inBackmode: Is backgrounding needed?
 *  char *rFile: Input files, if in args
 *  char *procArr[]: Processed input
 *  char *oFile: Output files, if in args
 *
 */
void procInput(const int shell_pid, bool *inBackmode, char *procArr[], 
               char *rFile, char *oFile) {

    char inArgs[MAX_LINE_LENGTH], *token = NULL, *savePtr = NULL, 
         s_pid[128], *expanded = NULL, *temp = NULL;
    int curs;

    // Convert the shell PID to a string for later use
    sprintf(s_pid, "%d", shell_pid);

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
        procArr[0] = '\0';
        return;
    }

    // Tokenize the input
    token = strtok_r(inArgs, " ", &savePtr);
    curs = 0;

    // Examine tokens for special chars and functions
    while (token != NULL) {

        // & -> Background process
        if (strcmp(token, "&") == 0) {
            // Set the background mode flag
            *inBackmode = true;
        }
        // < -> Input Filename
        else if (strcmp(token, "<") == 0) {
            // Store the input file
            token = strtok_r(NULL, " ", &savePtr);
            strcpy(rFile, token);
        }
        // > -> Output Filename
        else if (strcmp(token, ">") == 0) {
            // Store the output file
            token = strtok_r(NULL, " ", &savePtr);
            strcpy(oFile, token);
        }
        // User External Commands
        else {
            // Copy over the command to a buffer
            procArr[curs] = strdup(token);

            // Go through the args for $$
            for (int j = 0; j < strlen(procArr[curs]); j++) {
                // If $$ is the current token, expand to shell_pid
                if ((procArr[curs][j] == '$') && 
                    (procArr[curs][j + 1] == '$')) {
                                    
                    // Replace the shell PID in-place
                    // If we are not at the end of the string
                    if (strncmp(procArr[curs], "\0", j + 2) != 0) {

                        temp = strdup(procArr[curs] + j + 2);

                        procArr[curs][j] = '\0';

                        snprintf(procArr[curs], 256, "%s%d%s", 
                                 procArr[curs], shell_pid, temp); 

                        if (temp != NULL) free(temp);
                        temp = NULL;

                    } else {
                        procArr[curs][j] = '\0';
                        snprintf(procArr[curs], 256, "%s%d", 
                                 procArr[curs], shell_pid);

                    }

                }

            }
        }

        // Increment the counter
        curs++;
        token = strtok_r(NULL, " ", &savePtr);

    }

    // Add an additional NULL
    procArr[curs] = NULL;

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
        fflush(stdout);

    } else {
        // we got a signal from the user
        printf("terminated by signal %d\n", WTERMSIG(childStatus));
        fflush(stdout);
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
 *  struct sigaction sa_ign: Process signal handler
 *  struct sigaction sa_sigint: Process signal handler
 *  char *inFile: Input file
 *  char *outFile: Output file
 *
 */
void execUserCMD(char *input[], bool *isBackground, int status, 
                 struct sigaction sa_tstp, struct sigaction sa_sigint,
                 char *inFile, char *outFile) {

    int openFD, writeFD, resultStat;
    pid_t childPid = -5;
    
    // This mirrors Exploration: Process API - Executing a New Program

    // Spawn the child
    childPid = fork();

    switch (childPid) {
        case -1:
            // Could not spawn a child
            perror("Spawn Failed!\n");
            fflush(stdout);
            exit(1);

            break;

        case 0:
            // Take the handler, now hook ^Z
            sigaction(SIGTSTP, &sa_tstp, NULL);
            // And if we are not in the background, now hook ^C
            if (!*isBackground) sigaction(SIGINT, &sa_sigint, NULL);

            // If the user specified an input file redirect 
            if (strcmp(inFile, "") != 0) {
                // Open the input file
                openFD = open(inFile, O_RDONLY);

                // Check the input file descriptor
                if (openFD == -1) {
                    perror("Unable to open input file");
                    fflush(stdout);
                    exit(1);
                }

                // Copy the descriptor and assign
                resultStat = dup2(openFD, 0);

                // If the dup2 did not function correctly
                if (resultStat == -1) {
                    perror("Unable to assign input file");
                    fflush(stdout);
                    exit(2);
                }

                // Close
                fcntl(openFD, F_SETFD, FD_CLOEXEC);

            // If the input file is empty and we are in the background
            } else if ((strcmp(inFile, "") == 0) && *isBackground) {
                // Redirect to /dev/null
                openFD = ("/dev/null", O_RDONLY);

                // Check the input file descriptor
                if (openFD == -1) {
                    perror("Unable to open /dev/null");
                    fflush(stdout);
                    exit(1);
                }

                // Copy the descriptor and assign
                resultStat = dup2(openFD, 0);

                // If the dup2 did not function correctly
                if (resultStat == -1) {
                    perror("Unable to assign /dev/null");
                    fflush(stdout);
                    exit(2);
                }

                // Close
                fcntl(openFD, F_SETFD, FD_CLOEXEC);

            }
            
            // If the user specified an output file redirect
            if (strcmp(outFile, "") != 0) {
                // Open the output file
                writeFD = open(outFile, O_WRONLY | O_CREAT | O_TRUNC, 
                               S_IRUSR | S_IWUSR | S_IWGRP | S_IWOTH);

                // Check the output file descriptor
                if (writeFD == -1) {
                    perror("Unable to open output file");
                    fflush(stdout);
                    exit(1);
                }

                // Copy the descriptor and assign
                resultStat = dup2(writeFD, 1);

                // If the dup2 did not function correctly
                if (resultStat == -1) {
                    perror("Unable to assign output file");
                    fflush(stdout);
                    exit(2);
                }

                // Close
                fcntl(writeFD, F_SETFD, FD_CLOEXEC);

            // If there is no output redirect and we are in the background
            } else if ((strcmp(outFile, "") == 0) && *isBackground) {
                // Redirect to /dev/null
                writeFD = ("/dev/null", O_WRONLY | O_TRUNC);

                // Check the output file descriptor
                if (writeFD == -1) {
                    perror("Unable to open /dev/null");
                    fflush(stdout);
                    exit(1);
                }

                // Copy the descriptor and assign
                resultStat = dup2(writeFD, 1);

                // If the dup2 did not function correctly
                if (resultStat == -1) {
                    perror("Unable to assign /dev/null");
                    fflush(stdout);
                    exit(2);
                }

                // Close
                fcntl(openFD, F_SETFD, FD_CLOEXEC);

            }

            // Execute the user's command
            if (execvp(input[0], input) == -1) {
                // There was no valid command
                printf("%s: no such file or directory\n", input[0]);
                fflush(stdout);
                exit(2);
            }

            break;

        default:
            // Check for a background task and wait
            if (*isBackground && isBack) {
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
    char *inFile = NULL, *outFile = NULL, *input[MAX_ARGS], path[PATH_MAX];
    // Signal structs
    struct sigaction small_sigint = {0}, small_sigtstp = {0};

    // Initialize
    for (int i = 0; i < MAX_ARGS; i++) 
        input[i] = (char *)calloc(256, sizeof(char));

    // Allocate the filename buffers
    inFile = (char *)calloc(256, sizeof(char));
    outFile = (char *)calloc(256, sizeof(char));

    // Make the Signal Handlers
    small_sigint.sa_handler = SIG_DFL;
    sigfillset(&small_sigint.sa_mask);
    small_sigint.sa_flags = SA_RESTART;
    sigaction(SIGINT, &small_sigint, NULL);

    small_sigtstp.sa_handler = handleTSTP;
    sigfillset(&small_sigtstp.sa_mask);
    small_sigtstp.sa_flags = SA_RESTART;
    sigaction(SIGTSTP, &small_sigtstp, NULL);

    // Main Run Loop
    while (runLoop) {

        // Get and process stdin
        procInput(pid, &isBackgrounded, input, inFile, outFile);

        // Ignore comments and blanks
        if ((strncmp(input[0], "#", 1) == 0) || 
            (strcmp(input[0], "\0") == 0)) {
            continue;
        }
        // Exit commanded
        else if (strcmp("exit", input[0]) == 0) {
            runLoop = false;
        }
        // Change Directory "cd" commanded
        else if (strcmp("cd", input[0]) == 0) {
            // User specified a directory to change to
            if (input[1] != NULL) {
                // If the directory does not exist, then perror
                if (chdir(input[1]) == -1) {
                    printf("No directory found named %s", input[1]);
                    fflush(stdout);
                }
            } else {
                // Go to HOME
                getcwd(path, sizeof(path));
                chdir(path);

            }
        }
        // Status commanded
        else if (strcmp("status", input[0]) == 0) {
            printStatus(exitVal);
        }
        // Execute user command
        else {
            execUserCMD(input, &isBackgrounded, exitVal, small_sigtstp,
                        small_sigint, inFile, outFile);
        }

        // Reset the runtime vars
        isBackgrounded = false;
        inFile[0] = '\0';
        outFile[0] = '\0';
       
        for (int i = 0; i < MAX_ARGS; i++) {
            input[i] = '\0';
        }

    }

    // Clean Up
    if (inFile != NULL) free(inFile);
    inFile = NULL;

    if (outFile != NULL) free(outFile);
    outFile = NULL;

    for (int i = 0; i < MAX_ARGS; i++) {
        if (input[i] != NULL) free(input[i]);
        input[i] = NULL;
    }

    return EXIT_SUCCESS; 

}

