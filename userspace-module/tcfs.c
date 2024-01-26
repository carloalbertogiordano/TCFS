#define FUSE_USE_VERSION 30
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* For pread()/pwrite() */
#if __STDC_VERSION__ >= 199901L
#define _XOPEN_SOURCE 600
#else
#define _XOPEN_SOURCE 500
#endif /* __STDC_VERSION__ */

#include "utils/crypt-utils/crypt-utils.h"
#include "utils/tcfs_utils/tcfs_utils.h"
#include <argp.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h> /* Definition of AT_* constants */
#include <fuse3/fuse.h>
#include <limits.h>
#include <linux/limits.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

/**
 * @var root_path
 * @brief Contains the fullpath to the mounted directory
 * */
char *root_path;
/**
 * @var password
 * @brief Contains the password passed to TCFS when started
 * */
char *password;

static int tcfs_getxattr (const char *fuse_path, const char *name, char *value,
                          size_t size);

static int
tcfs_opendir (const char *fuse_path, struct fuse_file_info *fi)
{
  (void)fi;

  printf ("Called opendir %s\n", fuse_path);

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  const char *new_path = prefix_path (enc_fuse_path, root_path);
  printf ("\topendir new_path %s\n", new_path);

  DIR *dp = opendir (new_path);
  if (dp == NULL)
    {
      perror ("Could not open the directory");
      return -errno;
    }

  closedir (dp);
  return 0;
}

static int
tcfs_getattr (const char *fuse_path, struct stat *stbuf,
              struct fuse_file_info *fi)
{
  (void)fi;
  printf ("Called getattr on %s   %s\n", root_path, fuse_path);

  int res;

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  printf ("\tgetattr enc_fuse_path: %s\n", enc_fuse_path);
  const char *new_path = prefix_path (enc_fuse_path, root_path);
  printf ("\tgetattr new_path on %s\n", new_path);

  res = stat (new_path, stbuf);
  if (res == -1)
    {
      printf ("\taccess: Stat returned -1, err:%d\n", -errno);
      perror ("getattr err");
      return -errno;
    }

  return 0;
}

static int
tcfs_access (const char *fuse_path, int mask)
{
  printf ("Callen access on %s\n", fuse_path);
  int res;

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  const char *full_path = prefix_path (enc_fuse_path, root_path);
  printf ("\taccess encrypt_path %s\n", full_path);

  res = access (full_path, mask);
  if (res == -1)
    {
      perror ("access error");
      return -errno;
    }

  return 0;
}

static int
tcfs_readlink (const char *fuse_path, char *buf, size_t size)
{
  printf ("called readlink\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  char *path = prefix_path (enc_fuse_path, root_path);
  printf ("\treadlink on %s\n", path);

  size_t res;
  res = readlink (path, buf, size - 1);
  if (res == -1UL)
    {
      perror ("readlink error");
      return -errno;
    }

  buf[res] = '\0';
  return 0;
}

static int
tcfs_readdir (const char *fuse_path, void *buf, fuse_fill_dir_t filler,
              off_t offset, struct fuse_file_info *fi,
              enum fuse_readdir_flags frdf)
{
  (void)offset;
  (void)fi;
  (void)frdf;

  printf ("Called readdir %s\n", fuse_path);
  const char *enc_path = encrypt_path (fuse_path, password);
  char *path = prefix_path (enc_path, root_path);
  printf ("readdir on %s\n", path);

  DIR *dp = NULL;
  struct dirent *de;

  dp = opendir (path);
  if (dp == NULL)
    {
      perror ("Could not open the directory");
      return -errno;
    }
  printf ("Dir %s opened\n", path);

  while ((de = readdir (dp)) != NULL)
    {
      struct stat st;
      memset (&st, 0, sizeof (st));
      st.st_ino = de->d_ino;
      st.st_mode = de->d_type << 12;

      int filler_res = -1, can_break = 0;

      if ((strcmp (de->d_name, ".") == 0 || strcmp (de->d_name, "..") == 0
           || strcmp (de->d_name, "/") == 0))
        {
          printf ("ONE\n");
          filler_res = filler (buf, de->d_name, &st, 0, 0);
          if (filler_res != 0)
            {
              can_break = 1;
            }
        }
      else
        {
          printf ("\tchecking for %s is %s\n", de->d_name,
                  decrypt_file_name_with_hex (de->d_name, password));

          const char *dec_dirname = decrypt_path (de->d_name, password);
          if (dec_dirname == NULL){
              fprintf (stderr, "Could not decipher dir name");
              return -1;
            }

          //We must avoid the initial / of dec_dirname
          filler_res = filler (buf, dec_dirname+1, &st, 0, 0);
          if (filler_res != 0)
            {
              can_break = 1;
            }
        }

      printf ("FILLER RES: %d, CAN BREAK %d\n", filler_res, can_break);
      if (can_break == 1)
        {
          printf ("Breaking out\n");
          perror ("readdir error");
          closedir (dp);
          return -errno;
          break;
        }
    }

  closedir (dp);
  return 0;
}

static int
tcfs_mknod (const char *fuse_path, mode_t mode, dev_t rdev)
{
  printf ("Called mknod\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  char *path = prefix_path (enc_fuse_path, root_path);
  printf ("\tmknod on %s\n", path);

  int res;

  /* On Linux this could just be 'mknod(path, mode, rdev)' but this
     is more portable */
  if (S_ISREG (mode))
    {
      res = open (path, O_CREAT | O_EXCL | O_WRONLY, mode);
      if (res >= 0)
        res = close (res);
    }
  else if (S_ISFIFO (mode))
    res = mkfifo (path, mode);
  else
    res = mknod (path, mode, rdev);
  if (res == -1)
    return -errno;

  return 0;
}

static int
tcfs_mkdir (const char *fuse_path, mode_t mode)
{
  printf ("!!! Called mkdir on %s\n", fuse_path);

  const char *enc_path = encrypt_path (fuse_path, password);

  printf ("\tmkdir prefix_path (%s, %s)\n", enc_path, root_path);
  char *path = prefix_path (enc_path, root_path);
  printf ("\tmkdir %s\n", path);

  int res;
  res = mkdir (path, mode);
  if (res == -1)
    return -errno;

  return 0;
}

static int
tcfs_unlink (const char *fuse_path)
{
  printf ("Called unlink\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  char *path = prefix_path (enc_fuse_path, root_path);
  printf ("\tunlink on %s\n", path);

  int res;

  res = unlink (path);
  if (res == -1)
    return -errno;

  return 0;
}

static int
tcfs_rmdir (const char *fuse_path)
{
  printf ("Called rmdir\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  char *path = prefix_path (enc_fuse_path, root_path);
  printf ("\trmdir on %s\n", path);

  int res;

  res = rmdir (path);
  if (res == -1)
    return -errno;

  return 0;
}

static int
tcfs_symlink (const char *from, const char *to)
{
  printf ("Called symlink %s->%s\n", from, to);
  int res;

  const char *enc_from_path = encrypt_path_and_filename (from, password);
  char *enc_from = prefix_path (enc_from_path, root_path);
  const char *enc_to_path = encrypt_path_and_filename (to, password);
  char *enc_to = prefix_path (enc_to_path, root_path);
  printf ("\trmdir from %s to %s\n", enc_from_path, enc_to_path);

  res = symlink (enc_from, enc_to);
  if (res == -1)
    {
      perror ("symlink error");
      return -errno;
    }

  return 0;
}

static int
tcfs_rename (const char *from, const char *to, unsigned int flags)
{
  (void)flags; // FUSE does not use this parameter
  printf ("Called rename\n");
  int res;

  const char *enc_from_path = encrypt_path_and_filename (from, password);
  char *enc_from = prefix_path (enc_from_path, root_path);
  const char *enc_to_path = encrypt_path_and_filename (to, password);
  char *enc_to = prefix_path (enc_to_path, root_path);
  printf ("\trmdir from %s to %s\n", enc_from_path, enc_to_path);

  res = rename (enc_from, enc_to);
  if (res == -1)
    return -errno;

  return 0;
}

static int
tcfs_link (const char *from, const char *to)
{
  printf ("Called link\n");
  int res;

  const char *enc_from_path = encrypt_path_and_filename (from, password);
  char *enc_from = prefix_path (enc_from_path, root_path);
  const char *enc_to_path = encrypt_path_and_filename (to, password);
  char *enc_to = prefix_path (enc_to_path, root_path);
  printf ("\trmdir from %s to %s\n", enc_from, enc_to);

  res = link (enc_from, enc_to);
  if (res == -1)
    {
      perror ("link error");
      return -errno;
    }

  return 0;
}
static int
tcfs_chmod (const char *fuse_path, mode_t mode, struct fuse_file_info *fi)
{
  (void)fi;
  int res;

  printf ("Called chmod\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  printf ("\taccess encrypt_path %s\n", path);

  res = chmod (path, mode);
  if (res == -1)
    {
      perror ("chmod error");
      return -errno;
    }

  return 0;
}

static int
tcfs_chown (const char *fuse_path, uid_t uid, gid_t gid,
            struct fuse_file_info *fi)
{
  (void)fi;
  printf ("Called chown\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  printf ("\tchown encrypt_path %s\n", path);

  int res;
  res = lchown (path, uid, gid);
  if (res == -1)
    return -errno;

  return 0;
}

static int
tcfs_truncate (const char *fuse_path, off_t size, struct fuse_file_info *fi)
{
  (void)fi;
  printf ("Called truncate\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  printf ("\ttruncate encrypt_path %s\n", path);

  int res;
  res = truncate (path, size);
  if (res == -1)
    {
      perror ("truncate error");
      return -errno;
    }

  return 0;
}

// #ifdef HAVE_UTIMENSAT
static int
tcfs_utimens (const char *fuse_path, const struct timespec ts[2],
              struct fuse_file_info *fi)
{
  (void)fi;
  printf ("Called utimens\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  char *path = prefix_path (enc_fuse_path, root_path);
  printf ("\tutimesns on %s\n", path);

  int res;
  struct timeval tv[2];

  tv[0].tv_sec = ts[0].tv_sec;
  tv[0].tv_usec = ts[0].tv_nsec / 1000;
  tv[1].tv_sec = ts[1].tv_sec;
  tv[1].tv_usec = ts[1].tv_nsec / 1000;

  res = utimes (path, tv);
  if (res == -1)
    {
      perror ("utimes error");
      return -errno;
    }

  return 0;
}
// #endif

static int
tcfs_open (const char *fuse_path, struct fuse_file_info *fi)
{
  printf ("Called open\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  char *path = prefix_path (enc_fuse_path, root_path);
  printf ("\topen on %s\n", path);

  int res;

  res = open (path, fi->flags);
  if (res == -1)
    {
      perror ("open error");
      return -errno;
    }

  close (res);
  return 0;
}

static inline int
file_size (FILE *file)
{
  struct stat st;

  if (fstat (fileno (file), &st) == 0)
    return st.st_size;

  return -1;
}

static int
tcfs_read (const char *fuse_path, char *buf, size_t size, off_t offset,
           struct fuse_file_info *fi)
{
  (void)size;
  (void)fi;

  printf ("Calling read\n");
  FILE *path_ptr, *tmpf;
  char *path;
  int res;

  // Retrieve the username
  char username_buf[1024];
  size_t username_buf_size = 1024;
  get_user_name (username_buf, username_buf_size);

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);
  printf ("\tread on %s\n", path);

  path_ptr = fopen (path, "r");
  tmpf = tmpfile ();

  // Get key size
  char *size_key_char = malloc (sizeof (char) * 20);
  if (tcfs_getxattr (fuse_path, "user.key_len", size_key_char, 20) == -1)
    {
      perror ("Could not get file key size");
      return -errno;
    }
  ssize_t size_key = strtol (size_key_char, NULL, 10);

  // Retrive the file key
  unsigned char *encrypted_key = malloc ((size_key + 1) * sizeof (char));
  encrypted_key[size_key] = '\0';
  if (tcfs_getxattr (fuse_path, "user.key", (char *)encrypted_key, size_key)
      == -1)
    {
      perror ("Could not get encrypted key for file in tcfs_read");
      return -errno;
    }

  // Decrypt the file key
  unsigned char *decrypted_key;
  decrypted_key = decrypt_string (encrypted_key, password);

  /* Decrypt*/
  if (do_crypt (path_ptr, tmpf, DECRYPT, decrypted_key) != 1)
    {
      perror ("Err: do_crypt cannot decrypt file");
      return -errno;
    }

  /* Something went terribly wrong if this is the case. */
  if (path_ptr == NULL || tmpf == NULL)
    return -errno;

  if (fflush (tmpf) != 0)
    {
      perror ("Err: Cannot flush file in read process");
      return -errno;
    }
  if (fseek (tmpf, offset, SEEK_SET) != 0)
    {
      perror ("Err: cannot fseek while reading file");
      return -errno;
    }

  /* Read our tmpfile into the buffer. */
  res = fread (buf, 1, file_size (tmpf), tmpf);
  if (res == -1)
    {
      perror ("Err: cannot fread whine in read");
      res = -errno;
    }

  fclose (tmpf);
  fclose (path_ptr);
  free (encrypted_key);
  free (decrypted_key);
  return res;
}

static int
tcfs_write (const char *fuse_path, const char *buf, size_t size, off_t offset,
            struct fuse_file_info *fi)
{
  (void)fi;
  printf ("Called write\n");

  FILE *path_ptr, *tmpf;
  char *path;
  int res;
  int tmpf_descriptor;

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);
  printf ("\twrite on %s\n", path);

  path_ptr = fopen (path, "r+");
  tmpf = tmpfile ();
  tmpf_descriptor = fileno (tmpf);

  // Get the key size
  char *size_key_char = malloc (sizeof (char) * 20);
  if (tcfs_getxattr (fuse_path, "user.key_len", size_key_char, 20) == -1)
    {
      perror ("Could not get file key size");
      return -errno;
    }
  ssize_t size_key = strtol (size_key_char, NULL, 10);

  // Retrieve the file key
  unsigned char *encrypted_key
      = malloc (sizeof (unsigned char) * (size_key + 1));
  encrypted_key[size_key] = '\0';
  if (tcfs_getxattr (fuse_path, "user.key", (char *)encrypted_key, size_key)
      == -1)
    {
      perror ("Could not get file encrypted key in tcfs write");
      return -errno;
    }

  // Decrypt the file key
  unsigned char *decrypted_key = malloc (sizeof (unsigned char) * 33);
  decrypted_key[32] = '\0';
  decrypted_key = decrypt_string (encrypted_key, password);

  /* Something went terribly wrong if this is the case. */
  if (path_ptr == NULL || tmpf == NULL)
    {
      fprintf (stderr,
               "Something went terribly wrong, cannot create new files\n");
      return -errno;
    }

  /* if the file to write to exists, read it into the tempfile */
  if (tcfs_access (fuse_path, R_OK) == 0 && file_size (path_ptr) > 0)
    {
      if (do_crypt (path_ptr, tmpf, DECRYPT, decrypted_key) == 0)
        {
          perror ("do_crypt: Cannot cypher file\n");
          return --errno;
        }
      rewind (path_ptr);
      rewind (tmpf);
    }

  /* Read our tmpfile into the buffer. */
  res = pwrite (tmpf_descriptor, buf, size, offset);
  if (res == -1)
    {
      printf ("%d\n", res);
      perror ("pwrite: cannot read tmpfile into the buffer\n");
      res = -errno;
    }

  /* Encrypt*/
  if (do_crypt (tmpf, path_ptr, ENCRYPT, decrypted_key) == 0)
    {
      perror ("do_crypt 2: cannot cypher file\n");
      return -errno;
    }

  fclose (tmpf);
  fclose (path_ptr);
  free (encrypted_key);
  free (decrypted_key);

  return res;
}

static int
tcfs_statfs (const char *fuse_path, struct statvfs *stbuf)
{
  printf ("Called statfs\n");
  char *path = prefix_path (fuse_path, root_path);

  int res;

  res = statvfs (path, stbuf);
  if (res == -1)
    return -errno;

  return 0;
}

static int
tcfs_setxattr (const char *fuse_path, const char *name, const char *value,
               size_t size, int flags)
{
  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  printf ("\tsetxattr encrypt_path %s\n", path);

  int res = 1;
  if ((res = lsetxattr (path, name, value, size, flags)) == -1)
    perror ("tcfs_lsetxattr");
  if (res == -1)
    return -errno;
  return 0;
}

static int
tcfs_create (const char *fuse_path, mode_t mode, struct fuse_file_info *fi)
{
  (void)fi;
  (void)mode;
  printf ("Called create on %s\n", fuse_path);

  const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *fullpath = prefix_path (enc_fuse_path, root_path);
  printf ("\tcreating %s\n", fullpath);

  FILE *res;
  res = fopen (fullpath, "w");
  if (res == NULL)
    return -errno;

  // Flag file as encrypted
  if (tcfs_setxattr (fuse_path, "user.encrypted", "true", 4, 0)
      != 0) //(fsetxattr(fileno(res), "user.encrypted", "true", 4, 0) != 0)
    {
      fclose (res);
      return -errno;
    }

  // Generate and set a new encrypted key for the file
  unsigned char *key = malloc (sizeof (unsigned char) * 33);
  key[32] = '\0';
  generate_key (key);

  if (key == NULL)
    {
      perror ("cannot generate file key");
      return -errno;
    }
  if (is_valid_key (key) == 0)
    {
      fprintf (stderr, "Generated key size invalid\n");
      return -1;
    }

  // Encrypt the generated key
  int encrypted_key_len;
  unsigned char *encrypted_key
      = encrypt_string (key, password, &encrypted_key_len);

  // Set the file key
  if (tcfs_setxattr (fuse_path, "user.key", (const char *)encrypted_key,
                     encrypted_key_len, 0)
      != 0) //(fsetxattr(fileno(res), "user.key", encrypted_key, 32, 0) != 0)
    {
      perror ("Err setting key xattr");
      return -errno;
    }
  // Set key size
  char encrypted_key_len_char[20];
  snprintf (encrypted_key_len_char, sizeof (encrypted_key_len_char), "%d",
            encrypted_key_len);
  if (tcfs_setxattr (fuse_path, "user.key_len", encrypted_key_len_char,
                     sizeof (encrypted_key_len_char), 0)
      != 0) //(fsetxattr(fileno(res), "user.key", encrypted_key, 32, 0) != 0)
    {
      perror ("Err setting key_len xattr");
      return -errno;
    }

  free (encrypted_key);
  free (key);
  fclose (res);
  return 0;
}

static int
tcfs_release (const char *fuse_path, struct fuse_file_info *fi)
{
  const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  printf ("\trelease %s\n", path);

  /* Close the file */
  int res = close (fi->fh);
  if (res == -1)
    return -errno;

  /* Free the path */
  free ((void *)path);
  free ((void *)enc_fuse_path);

  return 0;
}

static int
tcfs_fsync (const char *fuse_path, int isdatasync, struct fuse_file_info *fi)
{
  /* Get the real path */
  const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  printf ("\tfsync %s\n", path);

  /* Synchronize the file's in-core state with storage device */
  int res;
  if (isdatasync)
    res = fdatasync ((int)fi->fh); // God, please do not let this overflow
  else
    res = fsync ((int)fi->fh); // Also this

  if (res == -1)
    return -errno;

  /* Free the path */
  free ((void *)path);

  return 0;
}

static int
tcfs_getxattr (const char *fuse_path, const char *name, char *value,
               size_t size)
{
  const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  printf ("\tgetxattr %s\n", path);

  printf ("Called getxattr on %s name:%s size:%zu\n", path, name, size);

  int res = (int)lgetxattr (path, name, value, size);
  if (res == -1)
    {
      perror ("Could not get xattr for file");
      return -errno;
    }
  return res;
}

static int
tcfs_listxattr (const char *fuse_path, char *list, size_t size)
{
  printf ("Called listxattr\n");
  const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  printf ("\tlistxattr %s\n", path);

  ssize_t res = llistxattr (path, list, size);
  if (res == -1L)
    {
      perror ("listxattr error");
      return -errno;
    }
  return (int)res; // FUSE wants an int back
}

static int
tcfs_removexattr (const char *fuse_path, const char *name)
{
  printf ("Called removexattr\n");
  const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  printf ("\tremovexattr %s\n", path);

  int res = lremovexattr (path, name);
  if (res == -1)
    {
      perror ("removexattr error");
      return -errno;
    }
  return 0;
}

static struct fuse_operations tcfs_oper = {
  .opendir = tcfs_opendir,
  .getattr = tcfs_getattr,
  .access = tcfs_access,
  .readlink = tcfs_readlink,
  .readdir = tcfs_readdir,
  .mknod = tcfs_mknod,
  .mkdir = tcfs_mkdir,
  .symlink = tcfs_symlink,
  .unlink = tcfs_unlink,
  .rmdir = tcfs_rmdir,
  .rename = tcfs_rename,
  .link = tcfs_link,
  .chmod = tcfs_chmod,
  .chown = tcfs_chown,
  .truncate = tcfs_truncate,
  .utimens = tcfs_utimens,
  .open = tcfs_open,
  .read = tcfs_read,
  .write = tcfs_write,
  .statfs = tcfs_statfs,
  .create = tcfs_create,
  .release = tcfs_release,
  .fsync = tcfs_fsync,
  .setxattr = tcfs_setxattr,
  .getxattr = tcfs_getxattr,
  .listxattr = tcfs_listxattr,
  .removexattr = tcfs_removexattr,
};

const char *argp_program_version = "TCFS Alpha";
const char *argp_program_bug_address = "carloalbertogiordano@duck.com";

static char doc[] = "This is an implementation on TCFS\ntcfs -s <source_path> "
                    "-d <dest_path> -p <password> [fuse arguments]";

static char args_doc[] = "";

static struct argp_option options[]
    = { { "source", 's', "SOURCE", 0, "Source file path", -1 },
        { "destination", 'd', "DESTINATION", 0, "Destination file path", -1 },
        { "password", 'p', "PASSWORD", 0, "Password", -1 },
        { NULL } };

struct arguments
{
  char *source;
  char *destination;
  char *password;
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 's':
      arguments->source = arg;
      break;
    case 'd':
      arguments->destination = arg;
      break;
    case 'p':
      arguments->password = arg;
      break;
    case ARGP_KEY_ARG:
      return ARGP_ERR_UNKNOWN;
    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, NULL, NULL };

int
main (int argc, char *argv[])
{
  umask (0);

  struct arguments arguments;

  arguments.source = NULL;
  arguments.destination = NULL;
  arguments.password = NULL;

  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  if (arguments.source == NULL || arguments.destination == NULL
      || arguments.password == NULL)
    {
      printf ("Err: You need to specify at least 3 arguments\n");
      return -1;
    }

  printf ("Source: %s\n", arguments.source);
  printf ("Destination: %s\n", arguments.destination);
  root_path = arguments.source;

  if (is_valid_key ((unsigned char *)arguments.password) == 0)
    {
      fprintf (stderr, "Inserted key not valid\n");
      return 1;
    }

  struct fuse_args args_fuse = FUSE_ARGS_INIT (0, NULL);
  fuse_opt_add_arg (&args_fuse, "./tcfs");
  fuse_opt_add_arg (&args_fuse, arguments.destination);
  fuse_opt_add_arg (&args_fuse,
                    "-f"); // TODO: this is forced for now, but will be passed
                           // via options in the future
  fuse_opt_add_arg (&args_fuse,
                    "-s"); // TODO: this is forced for now, but will be passed
                           // via options in the future

  // Print what we are passing to fuse TODO: This will be removed
  for (int i = 0; i < args_fuse.argc; i++)
    {
      printf ("%s ", args_fuse.argv[i]);
    }
  printf ("\n");

  // Get username
  /*
  char buf[1024];
  size_t buf_size = 1024;
  get_user_name(buf, buf_size);
  */

  password = arguments.password;

  return fuse_main (args_fuse.argc, args_fuse.argv, &tcfs_oper, NULL);
}
