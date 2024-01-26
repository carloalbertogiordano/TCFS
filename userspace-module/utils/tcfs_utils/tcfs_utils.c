#include "tcfs_utils.h"
#include "../crypt-utils/crypt-utils.h"

/**
 * @file tcfs_utils.c
 * @brief This file contains an assortment of functions used by tcfs.c \see
 * tcfs.c
 * */

/**
 * @brief  Fetch the username of the current user
 * @param buf The username will be written to this buffer
 * @param size  The size of the buffer
 * @return void
 * @note If an error occurs it will be printed and the buffer will not be
 * modified
 * */
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
 * @brief Check if a file is encrypted by TCFS
 * @param path  The fullpath of the file
 * @return \ret
 * */
int
is_encrypted (const char *path)
{
  int ret;
  char xattr_val[5];
  getxattr (path, "user.encrypted", xattr_val, sizeof (char) * 5);
  xattr_val[4] == '\n';

  return strcmp (xattr_val, "true") == 0 ? 1 : 0;
}

/* char *prefix_path(const char *path))
 * Purpose:
 * Args:
 *
 * Return: NULL on error, char* on success
 */
/**
 * @brief Prefix the realpath to the fuse path
 * @param path  The fuse path
 * @param realpath  The realpath to the directory mounted by TCFS
 * @return char * An allocated string containing the fullpath to the file
 * @note Please free the result after use
 * */
char *
prefix_path (const char *path, const char *realpath)
{
  if (path == NULL || realpath == NULL)
    {
      fprintf (stderr, "WARN: path or realpath is null\n");
      if (path != NULL) return (char *)path;
      if (realpath != NULL) return (char *) realpath;
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
 * @deprecated Currently it has no use
 * @brief Read a file, useful for debugging tmpfiles
 * @param file  The file to read
 * @return 0
 * @note It will print "file was empty" if the file was empty
 * */
int
read_file (FILE *file)
{
  int c;
  int file_contains_something = 0;
  FILE *read = file; /* don't move original file pointer */
  if (read)
    {
      while ((c = getc (read)) != EOF)
        {
          file_contains_something = 1;
          putc (c, stderr);
        }
    }
  if (!file_contains_something)
    fprintf (stderr, "file was empty\n");
  rewind (file);
  /* fseek(tmpf, offset, SEEK_END); */
  return 0;
}

/*
 * */
/* int get_encrypted_key(char *filepath, void *encrypted_key)
 * Purpose: Get the encrypted file key from its xattrs
 * Args:
 *
 */
/**
 * @brief Get the xattr value describing the key of a file
 * @deprecated There is no use currenly for this function. It was once used for
 * debugging
 * @param filepath  The full-path of the file
 * @param encrypted_key The buffer to save the encrypted key to
 * @return \ret
 * */
int
get_encrypted_key (char *filepath, unsigned char *encrypted_key)
{
  printf ("\tGet Encrypted key for file %s\n", filepath);
  if (is_encrypted (filepath) == 1)
    {
      printf ("\t\tencrypted file\n");

      FILE *src_file = fopen (filepath, "r");
      if (src_file == NULL)
        {
          fclose (src_file);
          perror ("Could not open the file to get the key");
          return -errno;
        }
      int src_fd;
      src_fd = fileno (src_file);
      if (src_fd == -1)
        {
          fclose (src_file);
          perror ("Could not get fd for the file");
          return -errno;
        }

      if (fgetxattr (src_fd, "user.key", encrypted_key, 33) != -1)
        {
          fclose (src_file);
          return 1;
        }
    }
  return 0;
}

/**
 * @brief Print the value of an aes key
 * @deprecated There is currently no use for this function
 * @warning THIS WILL PRINT THE AES KEY TO STDOUT. TCFS trusts the user by
 * design, but this is excessive
 * @param key The string containing the key
 * @return void
 * */
void
print_aes_key (unsigned char *key)
{
  printf ("AES HEX:%s -> ", key);
  for (int i = 0; i < 32; i++)
    {
      printf ("%02x", key[i]);
    }
  printf ("\n");
}

char *string_to_hex(const char *input) {
  printf ("\t\tSTRING TO HEX GOT %s\n", input);

  int i, len = strlen(input);
  char hex[3];
  char *output = (char *)malloc(2 * len + 1);

  if (!output) {
      perror("Errore di allocazione di memoria");
      return NULL;
    }

  output[0] = '\0'; // Assicura che la stringa risultante sia vuota all'inizio

  for (i = 0; i < len; i++) {
      sprintf(hex, "%02X", input[i]);
      strcat(output, hex);
    }

  printf ("\t\tSTRING TO HEX WILL RETURN %s\n", output);
  return output;
}

// Funzione per convertire esadecimale in una stringa
char *hex_to_string(const char *input) {
  printf ("\tHEX TO STRING GOT %s\n", input);
  int i, len = strlen(input) / 2;
  char *output = (char *)malloc(len + 1);

  if (!output) {
      perror("Errore di allocazione di memoria");
      return NULL;
    }

  output[0] = '\0'; // Assicura che la stringa risultante sia vuota all'inizio

  for (i = 0; i < len; i++) {
      char hex[3];
      hex[0] = input[2 * i];
      hex[1] = input[2 * i + 1];
      hex[2] = '\0';

      int decimal;
      sscanf(hex, "%X", &decimal);

      output[i] = (char)decimal;
    }

  output[len] = '\0'; // Aggiungi il terminatore null alla fine della stringa

  printf ("\tHEX TO STRING WILL RETURN %s\n", output);
  return output;
}
