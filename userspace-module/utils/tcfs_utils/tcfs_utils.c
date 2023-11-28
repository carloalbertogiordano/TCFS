#include "tcfs_utils.h"
#include "../crypt-utils/crypt-utils.h"

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

/* is_encrypted: returns 1 if file is encrypted, 0 otherwise*/
int
is_encrypted (const char *path)
{
  int ret;
  char xattr_val[5];
  getxattr (path, "user.encrypted", xattr_val, sizeof (char) * 5);
  xattr_val[4] == '\n';

  return strcmp (xattr_val, "true") == 0 ? 1 : 0;
}

char *
prefix_path (const char *path, const char *realpath)
{
  if (path == NULL || realpath == NULL)
    {
      perror ("Err: path or realpath is NULL");
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

/* read_file: for debugging tempfiles */
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
/* Get the xattr value describing the key of a file
 * return 1 on success else 0
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
/*For debugging only*/
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