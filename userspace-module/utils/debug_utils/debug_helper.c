#include "debug_helper.h"
#include "../tcfs_utils/tcfs_utils.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * @brief Path to the log file.
 */
#define LOGFILE "~/.tcfs/tcfs.log"

/**
 * @brief Flag indicating whether logging to console is enabled or not.
 */
static bool log_to_console = false;

/**
 * @brief Debug level for logging.
 */
static DebugLevel debug_level = DEBUG_NONE;

/**
 * @brief Enables or disables console logging.
 *
 * This function is used to control whether log messages are also printed to the console.
 * If @p enable is true, log messages will be printed to the console. If @p enable is false,
 * log messages will not be printed to the console.
 *
 * @param enable A boolean value indicating whether to enable (true) or disable (false) console logging.
 */
void
enable_console_logging (bool enable)
{
  log_to_console = enable;
}

void
set_debug_level (DebugLevel level)
{
  debug_level = level;
}

static void
log_to_file (const char *format, va_list args)
{
  const char *expanded_path = expand_path (LOGFILE);

  FILE *logFile = fopen (expanded_path, "a");
  if (logFile == NULL)
    {
      fprintf (stderr, "LogToFIle error, cannot open log file\n");
      free ((void *)expanded_path);
      return;
    }

  time_t rawtime;
  struct tm *timeinfo;
  time (&rawtime);
  timeinfo = localtime (&rawtime);

  fprintf (logFile, "[%04d-%02d-%02d %02d:%02d:%02d] ",
           timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, timeinfo->tm_mday,
           timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);

  vfprintf (logFile, format, args);

  fprintf (logFile, "\n");

  fclose (logFile);
  free ((void *)expanded_path);
}

static void
log_to_console_if_enabled (const char *format, va_list args)
{
  if (log_to_console)
    {
      vprintf (format, args);
      printf ("\n");
    }
}

void
logInfo (const char *format, ...)
{
  if (debug_level >= DEBUG_CALLS)
    {
      va_list args;
      va_start (args, format);

      va_list args_copy;
      va_copy (args_copy, args);

      log_to_file (format, args);
      log_to_console_if_enabled (format, args_copy);

      va_end (args);
      va_end (args_copy);
    }
}

void
logWarn (const char *format, ...)
{
  if (debug_level >= DEBUG_ERRORS)
    {
      va_list args;
      va_start (args, format);

      va_list args_copy;
      va_copy (args_copy, args);

      log_to_file (format, args);
      log_to_console_if_enabled (format, args_copy);

      va_end (args);
      va_end (args_copy);
    }
}

void
logErr (const char *format, ...)
{
  va_list args;
  va_start (args, format);

  va_list args_copy;
  va_copy (args_copy, args);

  log_to_file (format, args);
  log_to_console_if_enabled (format, args_copy);

  va_end (args);
  va_end (args_copy);
}

void
logDebug (const char *format, ...)
{
  if (debug_level >= DEBUG_ALL)
    {
      va_list args;
      va_start (args, format);

      va_list args_copy;
      va_copy (args_copy, args);

      log_to_file (format, args);
      log_to_console_if_enabled (format, args_copy);

      va_end (args);
      va_end (args_copy);
    }
}
