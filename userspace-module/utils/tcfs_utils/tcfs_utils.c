#include "tcfs_utils.h"
#include "../crypt-utils/crypt-utils.h"

/**
 * @file tcfs_utils.c
 * @brief This file contains an assortment of functions used by tcfs.c \see
 * tcfs.c
 * */

/**
 * @brief Fetch the username of the current user.
 * @param buf The buffer where the username will be written.
 * @param size The size of the buffer.
 * @return void
 * @note If an error occurs, it will be printed, and the buffer will not be
 * modified.
 */
void
get_user_name (char *buf, size_t size)
{
  uid_t uid = geteuid ();
  struct passwd *pw = getpwuid (uid);
  if (pw)
    snprintf (buf, size, "%s", pw->pw_name);
  else
    perror ("Error: Could not retrieve username.\n");
}

/**
 * @brief Check if a file is encrypted by TCFS.
 * @param path The full path of the file.
 * @return \ret
 */
int
is_encrypted (const char *path)
{
  int ret;
  char xattr_val[5];
  getxattr (path, "user.encrypted", xattr_val, sizeof (char) * 5);
  xattr_val[4] == '\n';

  return strcmp (xattr_val, "true") == 0 ? true : false;
}

/**
 * @brief Prefix the realpath to the fuse path.
 * @param path The fuse path.
 * @param realpath The realpath to the directory mounted by TCFS.
 * @return char * An allocated string containing the full path to the file.
 * @note Please free the result after use.
 */
char *
prefix_path (const char *path, const char *realpath)
{
  if (path == NULL || realpath == NULL)
    {
      fprintf (stderr, "WARN: path or realpath is null\n");
      if (path != NULL)
        return (char *)path;
      if (realpath != NULL)
        return (char *)realpath;
      return NULL;
    }

  size_t len = strlen (path) + strlen (realpath) + 1;
  char *root_dir = malloc (len * sizeof (char));

  if (root_dir == NULL)
    {
      perror ("Err: Could not allocate memory while in prefix_path");
      return NULL;
    }

  if (strcpy (root_dir, realpath) == NULL)
    {
      perror ("strcpy: Cannot copy path");
      return NULL;
    }
  if (strcat (root_dir, path) == NULL)
    {
      perror ("strcat: in prefix_path cannot concatenate the paths");
      return NULL;
    }
  return root_dir;
}

/**
 * @brief Print the value of an AES key.
 * @deprecated Currently has no use. Printing the AES key is considered
 * excessive.
 * @warning THIS WILL PRINT THE AES KEY TO STDOUT. TCFS trusts the user by
 * design, but this is excessive.
 * @param key The string containing the key.
 * @return void
 */
void
print_aes_key (unsigned char *key)
{
  logMessage ("AES HEX:%s -> ", key);
  for (int i = 0; i < 32; i++)
    {
      logMessage ("%02x", key[i]);
    }
  logMessage ("\n");
}

/**
 * @brief Convert a string to its hexadecimal representation.
 * @param input The input string.
 * @return char * The hexadecimal representation of the input string.
 * @note Remember to free the result after use.
 */
char *
string_to_hex (const char *input)
{
  logMessage ("\t\tSTRING TO HEX GOT %s\n", input);

  int i;
  size_t len = strlen (input);
  char hex[3];
  char *output = (char *)malloc (2 * len + 1);

  if (!output)
    {
      perror ("Errore di allocazione di memoria");
      return NULL;
    }

  // ensure that the resulting string is empty at the start.
  // Maybe it is not necessary, but some testing is required
  output[0] = '\0';

  for (i = 0; i < len; i++)
    {
      sprintf (hex, "%02X", input[i]);
      strcat (output, hex);
    }

  logMessage ("\t\tSTRING TO HEX WILL RETURN %s\n", output);
  return output;
}

/**
 * @brief Convert a hexadecimal string to its ASCII representation.
 * @param input The input hexadecimal string.
 * @return char * The ASCII representation of the input hexadecimal string.
 * @note Remember to free the result after use.
 */
char *
hex_to_string (const char *input)
{
  logMessage ("\tHEX TO STRING GOT %s\n", input);
  int i, len = strlen (input) / 2;
  char *output = (char *)malloc (len + 1);

  if (!output)
    {
      perror ("Errore di allocazione di memoria");
      return NULL;
    }

  // ensure that the resulting string is empty at the start.
  // Maybe it is not necessary, but some testing is required
  output[0] = '\0';

  for (i = 0; i < len; i++)
    {
      char hex[3];
      hex[0] = input[2 * i];
      hex[1] = input[2 * i + 1];
      hex[2] = '\0';

      int decimal;
      sscanf (hex, "%X", &decimal);

      output[i] = (char)decimal;
    }

  output[len] = '\0'; // Add a \0 terminator

  logMessage ("\tHEX TO STRING WILL RETURN %s\n", output);
  return output;
}

/**
 * @brief Logs a formatted message to a file with timestamp.
 *
 * This function logs a formatted message to a specified log file along with a
 * timestamp. It accepts a variable number of parameters, similar to printf.
 *
 * @param format The format string for the log message.
 * @param ... Additional parameters to be formatted into the log message.
 */
void logMessage(const char *format, ...)
{
  const char *home_path = getenv("HOME");
  if (home_path == NULL)
    {
      // Handle the case where HOME environment variable is not set
      perror("Cannot get HOME environment variable");
      home_path = "";
    }

  unsigned long log_path_length = strlen(home_path) + strlen(LOGFILE) + 1;
  char *log_path = malloc(log_path_length * sizeof(char));

  strcpy(log_path, home_path);
  strcat(log_path, LOGFILE);

  FILE *logFile = fopen(log_path, "a");
  if (logFile == NULL)
    {
      printf ("OPEN FAILED %s\n", log_path);
      perror("Cannot open log file");
      free(log_path);
      return;
    }

  time_t rawtime;
  struct tm *timeinfo;
  time(&rawtime);
  timeinfo = localtime(&rawtime);

  fprintf(logFile, "[%04d-%02d-%02d %02d:%02d:%02d] ",
           timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, timeinfo->tm_mday,
           timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);

  va_list args;
  va_start(args, format);
  vfprintf(logFile, format, args);
  va_end(args);

  fprintf(logFile, "\n");

  if (DEBUG)
    {
      va_start(args, format);
      vprintf(format, args);
      va_end(args);
      printf("\n");
    }

  // Chiudi il file di log e libera la memoria allocata
  fclose(logFile);
  free(log_path);
}
