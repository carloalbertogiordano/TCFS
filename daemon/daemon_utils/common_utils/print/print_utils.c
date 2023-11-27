#include "print_utils.h"

/**
 * @file print_utils.c
 * @brief This file defines some QoL functions
 * */

/**
 * @internal
 * @var int cleared
 * @brief If it is 0 the log file will be cleared, if is 1 the log file will we open as append
 * */
int cleared = 0;

/**
 * @internal \_func
 * @brief Log a message to stdout and to a file. The location is defined by logFile variable
 * @param
 * @return
 * @note
 * */
void log_message(const char *log){
    printf("%s\n", log);
    // Path of the log folder and log file
    const char *logFolder = "/var/log/tcfs";
    /**
     * @var lofFile
     * @brief path of the log file
     * */
    const char *logFile = "/var/log/tcfs/log.txt";

    // Check if the folder exists, otherwise create it
    struct stat st;
    if (stat(logFolder, &st) == -1) {
        mkdir(logFolder, 0700);
    }

    FILE *file;
    if (cleared == 0)
    {
        cleared = 1;
        file = fopen(logFile, "w");
    } else {
        file = fopen(logFile, "a");
    }

    // Open the log file in append mode
    if (file == NULL) {
        perror("Error opening the log file");
    }

    // Write the message to the log file
    fprintf(file, "%s\n", log);

    // Close the file
    fclose(file);
}

/**
 * @brief Format and print data as an error.
 * @param const char *format        the string that will formatted and printed
 * @param [ARGUMENTS]...       Print optional ARGUMENT(s) according to format
 * @return void
 * @note Will also log using systemD
 * @note \"ERROR=\" will be prepended to format
 * @note \"Err_Numebr:%d\" will be appended to the formatted string describing the error number
 * @note after Err_Number \"-> %s\" will be appended printing the std-error
 * */
void print_err(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    log_message(buffer);

    sd_journal_print(LOG_ERR, "ERROR=%s Err_Number:%d -> %s", buffer, errno, strerror(errno));
}
/**
 * @brief Format and print data as a message.
 * @param const char *format        the string that will formatted and printed
 * @param [ARGUMENTS]...       Print optional ARGUMENT(s) according to format
 * @return void
 * @note Will also log using systemD
 * @note \"MESSAGE=\" will be prepended to format
 * */
void print_msg(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    log_message(buffer);

    sd_journal_send("MESSAGE=%s", buffer, NULL);
}

/**
 * @brief Format and print data as a waring.
 * @param const char *format        the string that will formatted and printed
 * @param [ARGUMENTS]...       Print optional ARGUMENT(s) according to format
 * @return void
 * @note Will also log using systemD
 * @note \"WARNING=\" will be prepended to format
 * */
void print_warn(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    log_message(buffer);

    sd_journal_print(LOG_WARNING, "WARNING=%s", buffer, NULL);
}

/**
 * @brief Format and print data as a debug.
 * @param const char *format        the string that will formatted and printed
 * @param [ARGUMENTS]...       Print optional ARGUMENT(s) according to format
 * @return void
 * @note Will also log using systemD
 * @note \"DEBUG=\" will be prepended to format
 * */
void print_debug(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    log_message(buffer);

    sd_journal_print(LOG_DEBUG, "DEBUG=%s", buffer, NULL);
}