#ifndef DEBUG_UTILS_H_
#define DEBUG_UTILS_H_

#include <stdbool.h>

/**
 * @file debug_utils.h
 * @brief Utilities for logging and debugging.
 */

/**
 * @brief Enumeration for debug verbosity levels.
 */
typedef enum {
  DEBUG_NONE = 0,    /**< No debug prints */
  DEBUG_ERRORS = 1,  /**< Print only errors */
  DEBUG_CALLS = 2,   /**< Print only function calls */
  DEBUG_ALL = 3      /**< Print all debug information */
} DebugLevel;

/**
 * @brief Set the debug level.
 *
 * @param level The debug level to set.
 */
void set_debug_level(DebugLevel level);

/**
 * @brief Log a formatted informational message.
 *
 * This function logs a formatted message to a specified log file along with a
 * timestamp if logging to file is enabled.
 *
 * @param format The format string for the log message.
 * @param ... Additional parameters to be formatted into the log message.
 */
void logInfo(const char *format, ...);

/**
 * @brief Log a formatted warning message.
 *
 * This function logs a formatted warning message to a specified log file along
 * with a timestamp if logging to file is enabled.
 *
 * @param format The format string for the log message.
 * @param ... Additional parameters to be formatted into the log message.
 */
void logWarn(const char *format, ...);

/**
 * @brief Log a formatted error message.
 *
 * This function logs a formatted error message to a specified log file along
 * with a timestamp if logging to file is enabled. Additionally, it prints the
 * error message to the console if logging to console is enabled.
 *
 * @param format The format string for the log message.
 * @param ... Additional parameters to be formatted into the log message.
 */
void logErr(const char *format, ...);

/**
 * @brief Log a formatted debug message.
 *
 * This function logs a formatted debug message to a specified log file along
 * with a timestamp if logging to file is enabled. Additionally, it prints the
 * debug message to the console if logging to console is enabled and the debug
 * level is set to DEBUG_ALL.
 *
 * @param format The format string for the log message.
 * @param ... Additional parameters to be formatted into the log message.
 */
void logDebug(const char *format, ...);

void enable_console_logging (bool enable);

#endif /* DEBUG_UTILS_H_ */
