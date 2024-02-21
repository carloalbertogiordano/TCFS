#include "tcfs_utils.h"
#include "../crypt-utils/crypt-utils.h"
#include "../debug_utils/debug_helper.h"

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
    logErr ("Could not retrieve username");
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
      logWarn ("Path or realpath is null");
      if (path != NULL)
        return strdup (path); // Restituisci una copia di path
      if (realpath != NULL)
        return strdup (realpath); // Restituisci una copia di realpath
      return NULL;
    }

  // Copia di path e realpath
  char *path_clone = strdup (path);
  char *realpath_clone = strdup (realpath);

  if (path_clone == NULL || realpath_clone == NULL)
    {
      logErr ("Could not allocate memory while cloning strings");
      free (path_clone);
      free (realpath_clone);
      return NULL;
    }

  size_t len = strlen (path_clone) + strlen (realpath_clone) + 1;
  char *root_dir = malloc (len * sizeof (char));

  if (root_dir == NULL)
    {
      logErr ("Could not allocate memory while in prefix_path");
      free (path_clone);
      free (realpath_clone);
      return NULL;
    }

  // Copia realpath_clone in root_dir
  if (strcpy (root_dir, realpath_clone) == NULL)
    {
      logErr ("strcpy: Cannot copy realpath_clone");
      free (path_clone);
      free (realpath_clone);
      free (root_dir);
      return NULL;
    }

  // Concatena path_clone a root_dir
  if (strcat (root_dir, path_clone) == NULL)
    {
      logErr ("strcat: in prefix_path cannot concatenate the paths");
      free (path_clone);
      free (realpath_clone);
      free (root_dir);
      return NULL;
    }

  // Libera la memoria delle stringhe clonate
  free (path_clone);
  free (realpath_clone);

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
  logDebug ("AES HEX:%s -> ", key);
  for (int i = 0; i < 32; i++)
    {
      logDebug ("%02x", key[i]);
    }
  logDebug ("\n");
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
  int i;
  size_t len = strlen (input);
  char hex[3];
  char *output = (char *)malloc (2 * len + 1);

  if (!output)
    {
      logErr ("Error cannot allocate memory for string_to_hex output");
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
  size_t len = strlen (input) / 2;
  int i;
  char *output = (char *)malloc (len + 1);

  if (!output)
    {
      logErr ("Cannot allocate memory for hex_to_string output");
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

  logDebug ("\tHEX TO STRING WILL RETURN %s\n", output);
  return output;
}

/**
 * @brief Expands a given path, replacing '~' with the home directory.
 *
 * This function takes a path as input and returns a new path. If the input
 * path starts with '~', it replaces '~' with the path to the home directory.
 * If the home directory cannot be found, it returns NULL. If the input path
 * does not start with '~', it returns a duplicate of the input path.
 *
 * @param path The input path to be expanded.
 * @return A new string containing the expanded path, or NULL if the path
 * cannot be expanded.
 * @note The caller is responsible for freeing the returned string.
 */
char *
expand_path (const char *path)
{
  if (path[0] == '~')
    {
      const char *home_dir = getenv ("HOME");
      if (home_dir == NULL)
        {
          return NULL;
        }

      size_t home_len = strlen (home_dir);
      size_t path_len = strlen (path) - 1;
      size_t expanded_len = home_len + path_len + 1;

      char *expanded_path = malloc (expanded_len);
      if (expanded_path == NULL)
        {
          return NULL;
        }

      strcpy (expanded_path, home_dir);
      strcat (expanded_path, path + 1);

      return expanded_path;
    }
  else
    {
      return strdup (path);
    }
}
