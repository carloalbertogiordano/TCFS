/**
 * @file tcfs_operations.c
 * @brief Implementation of TCFS file system operations
 */

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

/**
 * @brief Opens a directory.
 *
 * This function is called when a directory is opened.
 *
 * @param fuse_path The path to the directory.
 * @param fi File information.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_opendir (const char *fuse_path, struct fuse_file_info *fi)
{
  (void)fi;

  logMessage ("Called opendir %s\n", fuse_path);

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  const char *new_path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\topendir new_path %s\n", new_path);

  DIR *dp = opendir (new_path);
  if (dp == NULL)
    {
      perror ("Could not open the directory");
      return -errno;
    }

  closedir (dp);
  return 0;
}

/**
 * @brief Gets file attributes.
 *
 * This function is called to get attributes for a file or directory.
 *
 * @param fuse_path The path to the file/directory.
 * @param stbuf Buffer to fill with attributes.
 * @param fi File information.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_getattr (const char *fuse_path, struct stat *stbuf,
              struct fuse_file_info *fi)
{
  (void)fi;
  logMessage ("Called getattr on %s%s\n", root_path, fuse_path);

  int res;
  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  logMessage ("\tgetattr enc_fuse_path: %s\n", enc_fuse_path);
  const char *new_path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\tgetattr new_path on %s\n", new_path);

  res = stat (new_path, stbuf);
  if (res == -1)
    {
      logMessage ("\taccess: Stat returned -1, err:%d\n", -errno);
      perror ("getattr err");
      return -errno;
    }

  return 0;
}

/**
 * @brief Checks file access permissions.
 *
 * This function is called to check file access permissions.
 *
 * @param fuse_path The path to the file/directory.
 * @param mask The requested access permissions.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_access (const char *fuse_path, int mask)
{
  logMessage ("Callen access on %s\n", fuse_path);
  int res;

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  const char *full_path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\taccess encrypt_path %s\n", full_path);

  res = access (full_path, mask);
  if (res == -1)
    {
      perror ("access error");
      return -errno;
    }

  return 0;
}

/**
 * @brief Reads the target of a symbolic link.
 *
 * This function is called to read the target of a symbolic link.
 *
 * @param fuse_path The path to the symbolic link.
 * @param buf Buffer to fill with the link target.
 * @param size The size of the buffer.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_readlink (const char *fuse_path, char *buf, size_t size)
{
  logMessage ("called readlink\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\treadlink on %s\n", path);

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

/**
 * @brief Reads a directory.
 *
 * This function is called to read the contents of a directory.
 *
 * @param fuse_path The path to the directory.
 * @param buf Buffer to fill with directory entries.
 * @param filler Callback function to add entries to the buffer.
 * @param offset The offset within the directory.
 * @param fi File information.
 * @param frdf Additional flags for readdir operation.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_readdir (const char *fuse_path, void *buf, fuse_fill_dir_t filler,
              off_t offset, struct fuse_file_info *fi,
              enum fuse_readdir_flags frdf)
{
  (void)offset;
  (void)fi;
  (void)frdf;

  logMessage ("Called readdir %s\n", fuse_path);
  const char *enc_path = encrypt_path (fuse_path, password);
  char *path = prefix_path (enc_path, root_path);
  logMessage ("readdir on %s\n", path);

  DIR *dp = NULL;
  struct dirent *de;

  dp = opendir (path);
  if (dp == NULL)
    {
      perror ("Could not open the directory");
      return -errno;
    }
  logMessage ("Dir %s opened\n", path);

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
          logMessage ("ONE\n");
          filler_res = filler (buf, de->d_name, &st, 0, 0);
          if (filler_res != 0)
            {
              can_break = 1;
            }
        }
      else
        {
          logMessage (
              "\tchecking for %s is %s\n", de->d_name,
              decrypt_file_name_with_hex ((const char *)de->d_name, password));

          const char *dec_dirname = decrypt_path (de->d_name, password);
          if (dec_dirname == NULL)
            {
              perror ("Could not decipher dir name");
              return -1;
            }

          // We must avoid the initial / of dec_dirname
          filler_res = filler (buf, dec_dirname + 1, &st, 0, 0);
          if (filler_res != 0)
            {
              can_break = 1;
            }
        }

      logMessage ("FILLER RES: %d, CAN BREAK %d\n", filler_res, can_break);
      if (can_break == 1)
        {
          logMessage ("Breaking out\n");
          perror ("readdir error");
          closedir (dp);
          return -errno;
          break;
        }
    }

  closedir (dp);
  return 0;
}

/**
 * @brief Creates a regular file or a special file (block or character).
 *
 * This function is called to create a regular file or a special file.
 *
 * @param fuse_path The path to the file.
 * @param mode File mode.
 * @param rdev Device numbers (if the file is a special file).
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_mknod (const char *fuse_path, mode_t mode, dev_t rdev)
{
  logMessage ("Called mknod\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\tmknod on %s\n", path);

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

/**
 * @brief Creates a directory.
 *
 * This function is called to create a directory.
 *
 * @param fuse_path The path to the directory.
 * @param mode Directory mode.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_mkdir (const char *fuse_path, mode_t mode)
{
  logMessage ("!!! Called mkdir on %s\n", fuse_path);

  const char *enc_path = encrypt_path (fuse_path, password);

  logMessage ("\tmkdir prefix_path (%s, %s)\n", enc_path, root_path);
  char *path = prefix_path (enc_path, root_path);
  logMessage ("\tmkdir %s\n", path);

  int res;
  res = mkdir (path, mode);
  if (res == -1)
    return -errno;

  return 0;
}

/**
 * @brief Removes a file.
 *
 * This function is called to remove a file.
 *
 * @param fuse_path The path to the file.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_unlink (const char *fuse_path)
{
  logMessage ("Called unlink\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\tunlink on %s\n", path);

  int res;

  res = unlink (path);
  if (res == -1)
    return -errno;

  return 0;
}

/**
 * @brief Removes a directory.
 *
 * This function is called to remove a directory.
 *
 * @param fuse_path The path to the directory.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_rmdir (const char *fuse_path)
{
  logMessage ("Called rmdir\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\trmdir on %s\n", path);

  int res;

  res = rmdir (path);
  if (res == -1)
    return -errno;

  return 0;
}

/**
 * @brief Creates a symbolic link.
 *
 * This function is called to create a symbolic link.
 *
 * @param from Source path of the symbolic link.
 * @param to Target path of the symbolic link.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_symlink (const char *from, const char *to)
{
  logMessage ("Called symlink %s->%s\n", from, to);
  int res;

  const char *enc_from_path = encrypt_path_and_filename (from, password);
  char *enc_from = prefix_path (enc_from_path, root_path);
  const char *enc_to_path = encrypt_path_and_filename (to, password);
  char *enc_to = prefix_path (enc_to_path, root_path);
  logMessage ("\trmdir from %s to %s\n", enc_from_path, enc_to_path);

  res = symlink (enc_from, enc_to);
  if (res == -1)
    {
      perror ("symlink error");
      return -errno;
    }

  return 0;
}

/**
 * @brief Renames a file or a directory.
 *
 * This function is called to rename a file or a directory.
 *
 * @param from Source path.
 * @param to Target path.
 * @param flags Flags for the rename operation.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_rename (const char *from, const char *to, unsigned int flags)
{
  (void)flags; // FUSE does not use this parameter
  logMessage ("Called rename\n");
  int res;

  const char *enc_from_path = encrypt_path_and_filename (from, password);
  char *enc_from = prefix_path (enc_from_path, root_path);
  const char *enc_to_path = encrypt_path_and_filename (to, password);
  char *enc_to = prefix_path (enc_to_path, root_path);
  logMessage ("\trmdir from %s to %s\n", enc_from_path, enc_to_path);

  res = rename (enc_from, enc_to);
  if (res == -1)
    return -errno;

  return 0;
}

/**
 * @brief Creates a hard link.
 *
 * This function is called to create a hard link.
 *
 * @param from Source path.
 * @param to Target path.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_link (const char *from, const char *to)
{
  logMessage ("Called link\n");
  int res;

  const char *enc_from_path = encrypt_path_and_filename (from, password);
  char *enc_from = prefix_path (enc_from_path, root_path);
  const char *enc_to_path = encrypt_path_and_filename (to, password);
  char *enc_to = prefix_path (enc_to_path, root_path);
  logMessage ("\trmdir from %s to %s\n", enc_from, enc_to);

  res = link (enc_from, enc_to);
  if (res == -1)
    {
      perror ("link error");
      return -errno;
    }

  return 0;
}

/**
 * @brief Changes the permissions of a file.
 *
 * This function is called to change the permissions of a file.
 *
 * @param fuse_path The path to the file.
 * @param mode New file mode.
 * @param fi File information.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_chmod (const char *fuse_path, mode_t mode, struct fuse_file_info *fi)
{
  (void)fi;
  int res;

  logMessage ("Called chmod\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\taccess encrypt_path %s\n", path);

  res = chmod (path, mode);
  if (res == -1)
    {
      perror ("chmod error");
      return -errno;
    }

  return 0;
}

/**
 * @brief Changes the owner and group of a file.
 *
 * This function is called to change the owner and group of a file.
 *
 * @param fuse_path The path to the file.
 * @param uid New user ID.
 * @param gid New group ID.
 * @param fi File information.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_chown (const char *fuse_path, uid_t uid, gid_t gid,
            struct fuse_file_info *fi)
{
  (void)fi;
  logMessage ("Called chown\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\tchown encrypt_path %s\n", path);

  int res;
  res = lchown (path, uid, gid);
  if (res == -1)
    return -errno;

  return 0;
}

/**
 * @brief Truncates or extends the size of a file.
 *
 * This function is called to truncate or extend the size of a file.
 *
 * @param fuse_path The path to the file.
 * @param size New size of the file.
 * @param fi File information.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_truncate (const char *fuse_path, off_t size, struct fuse_file_info *fi)
{
  (void)fi;
  logMessage ("Called truncate\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\ttruncate encrypt_path %s\n", path);

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
/**
 * @brief Modify the access and modification timestamps of a file in the TCFS
 * file system.
 *
 * This function is called when the `utimens` operation is performed on a file
 * in the TCFS.
 *
 * @param fuse_path The path of the encrypted file for which timestamps need to
 * be modified.
 * @param ts An array of two timespec structures containing the new access and
 * modification timestamps.
 * @param fi File information structure provided by FUSE.
 * @return 0 on success, negative error code on failure.
 *
 * @details
 * The `tcfs_utimens` function is invoked to modify the access and modification
 * timestamps of a file within the TCFS. It decodes the encrypted file path,
 * translates it into the actual file path on the underlying file system, and
 * then uses the `utimes` function to apply the changes to the file timestamps.
 *
 * @param fuse_path The path of the encrypted file within the TCFS.
 * @param ts An array containing two timespec structures. The first structure
 * represents the new access timestamp, and the second represents the new
 * modification timestamp.
 * @param fi File information provided by FUSE, which may be used to obtain
 * additional details about the file if needed.
 *
 * @return 0 on success. On failure, it returns a negative error code
 * representing the type of error encountered.
 *
 */
static int
tcfs_utimens (const char *fuse_path, const struct timespec ts[2],
              struct fuse_file_info *fi)
{
  (void)fi;
  logMessage ("Called utimens\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\tutimesns on %s\n", path);

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

/**
 * @brief Opens a file.
 *
 * This function is called to open a file.
 *
 * @param fuse_path The path to the file.
 * @param fi File information.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_open (const char *fuse_path, struct fuse_file_info *fi)
{
  logMessage ("Called open\n");

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\topen on %s\n", path);

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

/**
 * @brief Get the size of a file in the TCFS file system.
 *
 * This function is called when the `getattr` operation is performed on a file
 * in the TCFS to obtain file attributes.
 *
 * @param fuse_path The path of the encrypted file for which the size is
 * requested.
 * @param stbuf Buffer to store the file attributes, including the size.
 * @param fi File information structure provided by FUSE.
 * @return 0 on success, negative error code on failure.
 *
 * @details
 * The `tcfs_file_size` function is invoked to retrieve the size of a file
 * within the TCFS. It decodes the encrypted file path, translates it into the
 * actual file path on the underlying file system, and then uses the `getattr`
 * function to obtain the file attributes, including the file size.
 *
 * @param fuse_path The path of the encrypted file within the TCFS.
 * @param stbuf Buffer to store the file attributes, including the file size.
 * @param fi File information provided by FUSE, which may be used to obtain
 * additional details about the file if needed.
 *
 * @return 0 on success. On failure, it returns a negative error code
 * representing the type of error encountered.
 *
 * @note
 * - The function is a crucial part of file attribute retrieval, and the size
 * is a fundamental attribute of a file.
 * - The correct functioning of this function is essential for providing
 * accurate information about the file size.
 *
 * @warning
 * - Ensure that the function correctly translates the encrypted file path into
 * the actual file path on the underlying file system.
 * - Verify that the file attributes, especially the size, are accurately
 * retrieved and reported in the `stbuf` buffer.
 */
static inline int
file_size (FILE *file)
{
  struct stat st;

  if (fstat (fileno (file), &st) == 0)
    return st.st_size;

  return -1;
}

/**
 * @brief Reads data from an open file.
 *
 * This function is called to read data from an open file.
 *
 * @param fuse_path The path to the file.
 * @param buf Buffer to fill with data.
 * @param size Number of bytes to read.
 * @param offset Offset within the file.
 * @param fi File information.
 * @return The number of bytes read, or a negative error code on failure.
 */
static int
tcfs_read (const char *fuse_path, char *buf, size_t size, off_t offset,
           struct fuse_file_info *fi)
{
  (void)size;
  (void)fi;

  logMessage ("Calling read\n");
  FILE *path_ptr, *tmpf;
  char *path;
  int res;

  // Retrieve the username
  char username_buf[1024];
  size_t username_buf_size = 1024;
  get_user_name (username_buf, username_buf_size);

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\tread on %s\n", path);

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

/**
 * @brief Writes data to an open file.
 *
 * This function is called to write data to an open file.
 *
 * @param fuse_path The path to the file.
 * @param buf Data to write.
 * @param size Number of bytes to write.
 * @param offset Offset within the file.
 * @param fi File information.
 * @return The number of bytes written, or a negative error code on failure.
 */
static int
tcfs_write (const char *fuse_path, const char *buf, size_t size, off_t offset,
            struct fuse_file_info *fi)
{
  (void)fi;
  logMessage ("Called write\n");

  FILE *path_ptr, *tmpf;
  char *path;
  int res;
  int tmpf_descriptor;

  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\twrite on %s\n", path);

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
      perror ("Something went terribly wrong, cannot create new files");
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
      logMessage ("%d\n", res);
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

/**
 * @brief Get file system statistics.
 *
 * This function is called when the `statfs` operation is performed to obtain
 * statistics about the TCFS file system.
 *
 * @param fuse_path The path of the file system for which statistics are
 * requested.
 * @param stbuf Buffer to store file system statistics.
 * @return 0 on success, negative error code on failure.
 *
 * @details
 * The `tcfs_statfs` function is invoked to retrieve statistics about the TCFS
 * file system. It may include information such as the total size, free space,
 * and available space.
 *
 * @param fuse_path The path of the file system within the TCFS.
 * @param stbuf Buffer to store the file system statistics.
 *
 * @return 0 on success. On failure, it returns a negative error code
 * representing the type of error encountered.
 *
 * @note
 * - The function is essential for providing information about the overall
 * status of the TCFS file system.
 * - Ensure that the file system statistics are accurately retrieved and
 * reported in the `stbuf` buffer.
 *
 * @warning
 * - Verify that the function correctly handles errors and returns the
 * appropriate error codes.
 * - The accuracy of the reported statistics is crucial for applications that
 * rely on file system information.
 */
static int
tcfs_statfs (const char *fuse_path, struct statvfs *stbuf)
{
  logMessage ("Called statfs\n");
  char *path = prefix_path (fuse_path, root_path);

  int res;

  res = statvfs (path, stbuf);
  if (res == -1)
    return -errno;

  return 0;
}

/**
 * @brief Sets extended attributes.
 *
 * This function is called to set extended attributes.
 *
 * @param fuse_path The path to the file.
 * @param name Attribute name.
 * @param value Attribute value.
 * @param size Size of the value.
 * @param flags Flags for the setxattr operation.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_setxattr (const char *fuse_path, const char *name, const char *value,
               size_t size, int flags)
{
  const char *enc_fuse_path = encrypt_path (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\tsetxattr encrypt_path %s\n", path);

  int res = 1;
  if ((res = lsetxattr (path, name, value, size, flags)) == -1)
    perror ("tcfs_lsetxattr");
  if (res == -1)
    return -errno;
  return 0;
}

/**
 * @brief Create and open a file.
 *
 * This function is called when a new file is created in the TCFS file system.
 *
 * @param fuse_path The path of the file to be created.
 * @param mode The mode of the file (permissions).
 * @param fi File information, including flags and an open file handle.
 * @return 0 on success, negative error code on failure.
 *
 * @details
 * The `create` function is invoked when a new file is created in the TCFS file
 * system. It is responsible for setting up the necessary data structures,
 * allocating resources, and opening the file for subsequent read and write
 * operations.
 *
 * @param fuse_path The path of the file within the TCFS.
 * @param mode The mode of the file, specifying permissions and other
 * attributes.
 * @param fi File information containing flags and an open file handle.
 *
 * @return 0 on success. On failure, it returns a negative error code
 * representing the type of error encountered.
 *
 * @note
 * - The function must create the file and return an open file handle in the
 * `fi` structure.
 * - Ensure proper handling of file permissions, resource allocation, and any
 * other relevant attributes.
 *
 * @warning
 * - Verify that the function correctly handles errors and returns the
 * appropriate error codes.
 * - Implement necessary checks to ensure the file is created successfully and
 * is ready for subsequent operations.
 */
static int
tcfs_create (const char *fuse_path, mode_t mode, struct fuse_file_info *fi)
{
  (void)fi;
  (void)mode;
  logMessage ("Called create on %s\n", fuse_path);

  const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *fullpath = prefix_path (enc_fuse_path, root_path);
  logMessage ("\tcreating %s\n", fullpath);

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
      perror ("Generated key size invalid\n");
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

/**
 * @brief Releases an open file.
 *
 * This function is called to release an open file.
 *
 * @param fuse_path The path to the file.
 * @param fi File information.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_release (const char *fuse_path, struct fuse_file_info *fi)
{
  const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\trelease %s\n", path);

  /* Close the file */
  int res = close (fi->fh);
  if (res == -1)
    return -errno;

  /* Free the path */
  free ((void *)path);
  free ((void *)enc_fuse_path);

  return 0;
}

/**
 * @brief Synchronizes file contents.
 *
 * This function is called to synchronize file contents.
 *
 * @param fuse_path The path to the file.
 * @param datasync Flag indicating whether to sync only data.
 * @param fi File information.
 * @return 0 on success, a negative error code on failure.
 */
static int
tcfs_fsync (const char *fuse_path, int isdatasync, struct fuse_file_info *fi)
{
  /* Get the real path */
  const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\tfsync %s\n", path);

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

/**
 * @brief Get extended attribute data.
 *
 * This function is called to retrieve the value of an extended attribute for a
 * specified file or directory.
 *
 * @param fuse_path The path of the file or directory within the TCFS.
 * @param name The name of the extended attribute.
 * @param value Buffer to store the value of the extended attribute.
 * @param size The size of the buffer.
 * @return Size of the extended attribute value on success, negative error code
 * on failure.
 *
 * @details
 * The `getxattr` function is invoked to obtain the value of an extended
 * attribute associated with a file or directory within the TCFS file system.
 * The attribute value is stored in the provided buffer (`value`) with a
 * specified size.
 *
 * @param fuse_path The path of the file or directory.
 * @param name The name of the extended attribute to retrieve.
 * @param value Buffer to store the value of the extended attribute.
 * @param size The size of the buffer.
 *
 * @return On success, the function returns the size of the extended attribute
 * value. On failure, it returns a negative error code representing the type of
 * error encountered.
 *
 * @note
 * - The function must ensure that the attribute value is properly retrieved
 * and stored in the provided buffer.
 * - Verify that the correct error codes are returned in case of failures or
 * insufficient buffer size.
 * - Implement appropriate checks to handle different scenarios and edge cases.
 */
static int
tcfs_getxattr (const char *fuse_path, const char *name, char *value,
               size_t size)
{
  const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\tgetxattr %s\n", path);

  logMessage ("Called getxattr on %s name:%s size:%zu\n", path, name, size);

  int res = (int)lgetxattr (path, name, value, size);
  if (res == -1)
    {
      perror ("Could not get xattr for file");
      return -errno;
    }
  return res;
}

/**
 * @brief Lists extended attributes.
 *
 * This function is called to list extended attributes.
 *
 * @param fuse_path The path to the file.
 * @param list Buffer to fill with the attribute list.
 * @param size Size of the buffer.
 * @return Size of the attribute list on success, a negative error code on
 * failure.
 */
static int
tcfs_listxattr (const char *fuse_path, char *list, size_t size)
{
  logMessage ("Called listxattr\n");
  const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\tlistxattr %s\n", path);

  ssize_t res = llistxattr (path, list, size);
  if (res == -1L)
    {
      perror ("listxattr error");
      return -errno;
    }
  return (int)res; // FUSE wants an int back
}

/**
 * @brief Remove an extended attribute.
 *
 * This function is called to remove an extended attribute for a specified file
 * or directory.
 *
 * @param fuse_path The path of the file or directory within the TCFS.
 * @param name The name of the extended attribute to remove.
 * @return 0 on success, negative error code on failure.
 *
 * @details
 * The `removexattr` function is invoked to remove the specified extended
 * attribute associated with a file or directory within the TCFS file system.
 *
 * @param fuse_path The path of the file or directory.
 * @param name The name of the extended attribute to remove.
 *
 * @return On success, the function returns 0.
 *         On failure, it returns a negative error code representing the type
 * of error encountered.
 *
 * @note
 * - The function must ensure the proper removal of the specified extended
 * attribute.
 * - Verify that the correct error codes are returned in case of failures.
 * - Implement appropriate checks to handle different scenarios and edge cases.
 */
static int
tcfs_removexattr (const char *fuse_path, const char *name)
{
  logMessage ("Called removexattr\n");
  const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("\tremovexattr %s\n", path);

  int res = lremovexattr (path, name);
  if (res == -1)
    {
      perror ("removexattr error");
      return -errno;
    }
  return 0;
}

/**
 * @brief TCFS file system operations.
 *
 * This structure defines the operations supported by the TCFS file system.
 */
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

/**
 * @brief TCFS version information.
 */
const char *argp_program_version = "TCFS Alpha";

/**
 * @brief TCFS bug report email address.
 */
const char *argp_program_bug_address = "carloalbertogiordano@duck.com";

/**
 * @brief Documentation string for TCFS.
 */
static char doc[] = "This is an implementation on TCFS\ntcfs -s <source_path> "
                    "-d <dest_path> -p <password> [fuse arguments]";

/**
 * @brief Argument documentation string for TCFS.
 */
static char args_doc[] = "";

/**
 * @brief TCFS command-line options.
 */
static struct argp_option options[]
    = { { "source", 's', "SOURCE", 0, "Source file path", -1 },
        { "destination", 'd', "DESTINATION", 0, "Destination file path", -1 },
        { "password", 'p', "PASSWORD", 0, "Password", -1 },
        { NULL } };

/**
 * @brief Structure to store command-line arguments.
 */
struct arguments
{
  char *source;
  char *destination;
  char *password;
};

/**
 * @brief Parse command-line options.
 *
 * @param key Option key.
 * @param arg Option argument.
 * @param state Parser state.
 *
 * @return 0 on success, error code on failure.
 */
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

/**
 * @brief TCFS argp structure.
 */
static struct argp argp = { options, parse_opt, args_doc, doc, 0, NULL, NULL };

/**
 * @brief Main entry point for TCFS.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line arguments.
 *
 * @return 0 on success, error code on failure.
 */
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
      logMessage ("Err: You need to specify at least 3 arguments\n");
      return -1;
    }

  logMessage ("Source: %s\n", arguments.source);
  logMessage ("Destination: %s\n", arguments.destination);
  root_path = arguments.source;

  if (is_valid_key ((unsigned char *)arguments.password) == 0)
    {
      logMessage ("ERR: Inserted key not valid\n");
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
      logMessage ("%s ", args_fuse.argv[i]);
    }
  logMessage ("\n");

  password = arguments.password;

  return fuse_main (args_fuse.argc, args_fuse.argv, &tcfs_oper, NULL);
}
