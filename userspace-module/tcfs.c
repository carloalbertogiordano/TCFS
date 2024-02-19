/**
 * @file tcfs_operations.c
 * @brief Implementation of TCFS file system operations
 */

#define FUSE_USE_VERSION 30

/* For pread()/pwrite() */
#if __STDC_VERSION__ >= 199901L
#define _XOPEN_SOURCE 600
#else
#define _XOPEN_SOURCE 500
#endif /* __STDC_VERSION__ */

#define TCFS_SUCCESS 0
#define ERR_inval_arg_len 1
#define ERR_inval_key 2
#define ERR_inval_enc_dir_name 3
#define ERR_inval_file_size 4
#define ERR_inval_read_buf_size 5

#include "utils/config_utils/yaml_loader.h"
#include "utils/crypt-utils/crypt-utils.h"
#include "utils/tcfs_utils/tcfs_utils.h"
#include <argp.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h> /* Definition of AT_* constants */
#include <fuse3/fuse.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <unistd.h>

#define IV_ATTR_NAME "user.iv"

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

static jmp_buf jump_buffer;

static int tcfs_getxattr (const char *fuse_path, const char *name, char *value,
                          size_t size);
static int tcfs_setxattr (const char *fuse_path, const char *name,
                          const char *value, size_t size, int flags);

/**
 * @brief Opens a directory.
 *
 * This function is called when a directory is opened.
 *
 * @param fuse_path The path to the directory.
 * @param fi File information.
 * @return TCFS_SUCCESS on success, a negative error code on failure.
 */
static int
tcfs_opendir (const char *fuse_path, struct fuse_file_info *fi)
{
  (void)fi;
  const char *enc_fuse_path = NULL;
  const char *new_path = NULL;
  DIR *dp = NULL;

  if (setjmp (jump_buffer) != 0)
    {
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
      if (new_path)
        free ((void *)new_path);
      if (dp)
        closedir (dp);
      logErr ("occurred in opendir");
      return -errno;
    }

  logInfo("Called opendir %s\n", fuse_path);

  enc_fuse_path = encrypt_path (fuse_path, password);
  new_path = prefix_path (enc_fuse_path, root_path);
  logInfo ("\topendir new_path %s\n", new_path);

  dp = opendir (new_path);
  if (dp == NULL)
    {
      longjmp (jump_buffer, 1);
    }

  free ((void *)enc_fuse_path);
  free ((void *)new_path);
  closedir (dp);
  return TCFS_SUCCESS;
}

/**
 * @brief Gets file attributes.
 *
 * This function is called to get attributes for a file or directory.
 *
 * @param fuse_path The path to the file/directory.
 * @param stbuf Buffer to fill with attributes.
 * @param fi File information.
 * @return TCFS_SUCCESS on success, a negative error code on failure.
 */
static int
tcfs_getattr (const char *fuse_path, struct stat *stbuf,
              struct fuse_file_info *fi)
{
  (void)fi;
  logInfo ("Called getattr on %s%s\n", root_path, fuse_path);

  int res;
  const char *enc_fuse_path = NULL;
  const char *new_path = NULL;

  if (setjmp (jump_buffer) != 0)
    {
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
      if (new_path)
        free ((void *)new_path);
      logErr ("Error occured in getattr");
      return -errno;
    }

  enc_fuse_path = encrypt_path (fuse_path, password);
  logInfo ("\tgetattr enc_fuse_path: %s\n", enc_fuse_path);
  new_path = prefix_path (enc_fuse_path, root_path);
  logInfo ("\tgetattr new_path on %s\n", new_path);

  res = stat (new_path, stbuf);
  if (res == -1)
    {
      logErr("\taccess: Stat returned -1, err:%d\n", -errno);
      longjmp (jump_buffer, 1);
    }

  free ((void *)new_path);
  free ((void *)enc_fuse_path);
  return TCFS_SUCCESS;
}

/**
 * @brief Checks file access permissions.
 *
 * This function is called to check file access permissions.
 *
 * @param fuse_path The path to the file/directory.
 * @param mask The requested access permissions.
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_access (const char *fuse_path, int mask)
{
  logInfo ("Callen access on %s\n", fuse_path);
  int res;
  const char *enc_fuse_path = NULL;
  const char *full_path = NULL;

  if (setjmp (jump_buffer) != 0)
    {
      if (full_path)
        free ((void *)full_path);
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
      logErr ("Error in access");
      return -errno;
    }

  enc_fuse_path = encrypt_path (fuse_path, password);
  full_path = prefix_path (enc_fuse_path, root_path);
  logInfo ("\taccess encrypt_path %s\n", full_path);

  res = access (full_path, mask);
  if (res == -1)
    {
      longjmp (jump_buffer, 1);
    }

  free ((void *)full_path);
  free ((void *)enc_fuse_path);

  return TCFS_SUCCESS;
}

/**
 * @brief Reads the target of a symbolic link.
 *
 * This function is called to read the target of a symbolic link.
 *
 * @param fuse_path The path to the symbolic link.
 * @param buf Buffer to fill with the link target.
 * @param size The size of the buffer.
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_readlink (const char *fuse_path, char *buf, size_t size)
{
  logInfo ("called readlink\n");

  const char *enc_fuse_path = NULL;
  char *path = NULL;
  size_t res;

  if (setjmp (jump_buffer) != 0)
    {
      if (path)
        free ((void *)path);
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
      logErr ("Error in readlink");
      return -errno;
    }

  enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);
  logInfo ("\treadlink on %s\n", path);

  res = readlink (path, buf, size - 1);
  if (res == -1UL)
    {
      longjmp (jump_buffer, 1);
    }
  buf[res] = '\0';

  free ((void *)path);
  free ((void *)enc_fuse_path);

  return TCFS_SUCCESS;
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
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_readdir (const char *fuse_path, void *buf, fuse_fill_dir_t filler,
              off_t offset, struct fuse_file_info *fi,
              enum fuse_readdir_flags frdf)
{
  (void)offset;
  (void)fi;
  (void)frdf;

  const char *enc_path = NULL;
  char *path = NULL;
  DIR *dp = NULL;
  struct dirent *de;
  int error_return_number = TCFS_SUCCESS;

  if (setjmp (jump_buffer) != 0)
    {
      if (path)
        free ((void *)path);
      if (enc_path)
        free ((void *)enc_path);
      if (dp)
        closedir (dp);
      if (de)
        free ((void *)de);
      logErr ("Error in readdir");
      return -error_return_number;
    }

  logInfo ("Called readdir %s\n", fuse_path);
  enc_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_path, root_path);
  logInfo ("readdir on %s\n", path);

  dp = opendir (path);
  if (dp == NULL)
    {
      error_return_number = errno;
      longjmp (jump_buffer, 1);
    }
  logInfo ("Dir %s opened\n", path);

  while ((de = readdir (dp)) != NULL)
    {
      struct stat st;
      memset (&st, 0, sizeof (st));
      st.st_ino = de->d_ino;
      st.st_mode = de->d_type << 12;

      int filler_res = -1, can_break = false;

      if ((strcmp (de->d_name, ".") == 0 || strcmp (de->d_name, "..") == 0
           || strcmp (de->d_name, "/") == 0))
        {
          filler_res = filler (buf, de->d_name, &st, 0, 0);
          if (filler_res != 0)
            {
              can_break = true;
            }
        }
      else
        {
          logInfo (
              "\tchecking foreturn -errno;r %s is %s\n", de->d_name,
              decrypt_file_name_with_hex ((const char *)de->d_name, password));

          const char *dec_dirname = decrypt_path (de->d_name, password);
          if (dec_dirname == NULL)
            {
              error_return_number = -ERR_inval_enc_dir_name;
              longjmp (jump_buffer, 1);
            }

          // We must avoid the initial / of dec_dirname
          filler_res = filler (buf, dec_dirname + 1, &st, 0, 0);
          if (filler_res != 0)
            {
              can_break = true;
            }
        }

      logInfo ("FILLER RES: %d, CAN BREAK %d\n", filler_res, can_break);
      if (can_break)
        {
          logInfo ("Breaking out\n");
          error_return_number = errno;
          longjmp (jump_buffer, 1);
          break;
        }
    }

  free ((void *)path);
  free ((void *)enc_path);
  closedir (dp);
  free ((void *)de);

  return TCFS_SUCCESS;
}

/**
 * @brief Creates a regular file or a special file (block or character).
 *
 * This function is called to create a regular file or a special file.
 *
 * @param fuse_path The path to the file.
 * @param mode File mode.
 * @param rdev Device numbers (if the file is a special file).
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_mknod (const char *fuse_path, mode_t mode, dev_t rdev)
{
  logInfo ("Called mknod\n");

  const char *enc_fuse_path = NULL;
  char *path = NULL;
  int res;

  if (setjmp (jump_buffer) != 0)
    {
      if (path)
        free ((void *)path);
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
      logErr ("Error in mknod");
      return -errno;
    }

  enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);
  logInfo ("\tmknod on %s\n", path);

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
    longjmp (jump_buffer, 1);

  free ((void *)path);
  free ((void *)enc_fuse_path);

  return TCFS_SUCCESS;
}

/**
 * @brief Creates a directory.
 *
 * This function is called to create a directory.
 *
 * @param fuse_path The path to the directory.
 * @param mode Directory mode.
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_mkdir (const char *fuse_path, mode_t mode)
{
  const char *enc_path = NULL;
  char *path = NULL;
  int res;

  if (setjmp (jump_buffer) != 0)
    {
      if (path)
        free ((void *)path);
      if (enc_path)
        free ((void *)enc_path);
      logErr ("Error in mkdir");
      return -errno;
    }

  logInfo ("Called mkdir on %s\n", fuse_path);

  enc_path = encrypt_path (fuse_path, password);
  logInfo ("\tmkdir prefix_path (%s, %s)\n", enc_path, root_path);
  path = prefix_path (enc_path, root_path);
  logInfo ("\tmkdir %s\n", path);

  res = mkdir (path, mode);
  if (res == -1)
    longjmp (jump_buffer, 1);

  free ((void *)path);
  free ((void *)enc_path);

  return TCFS_SUCCESS;
}

/**
 * @brief Removes a file.
 *
 * This function is called to remove a file.
 *
 * @param fuse_path The path to the file.
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_unlink (const char *fuse_path)
{
  const char *enc_fuse_path = NULL;
  char *path = NULL;
  int res;

  if (setjmp (jump_buffer) != 0)
    {
      if (path)
        free ((void *)path);
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
      logErr ("Error in unlink");
      return -errno;
    }

  logInfo ("Called unlink\n");

  enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);
  logInfo ("\tunlink on %s\n", path);

  res = unlink (path);
  if (res == -1)
    longjmp (jump_buffer, 1);

  free ((void *)path);
  free ((void *)enc_fuse_path);

  return TCFS_SUCCESS;
}

/**
 * @brief Removes a directory.
 *
 * This function is called to remove a directory.
 *
 * @param fuse_path The path to the directory.
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_rmdir (const char *fuse_path)
{
  const char *enc_fuse_path = NULL;
  char *path = NULL;
  int res;

  if (setjmp (jump_buffer) != 0)
    {
      if (path)
        free ((void *)path);
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
    }

  logInfo ("Called rmdir\n");

  enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);
  logInfo ("\trmdir on %s\n", path);

  res = rmdir (path);
  if (res == -1)
    longjmp (jump_buffer, 1);

  free ((void *)path);
  free ((void *)enc_fuse_path);

  return TCFS_SUCCESS;
}

/**
 * @brief Creates a symbolic link.
 *
 * This function is called to create a symbolic link.
 *
 * @param from Source path of the symbolic link.
 * @param to Target path of the symbolic link.
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_symlink (const char *from, const char *to)
{
  const char *enc_from_path = NULL;
  char *enc_from = NULL;
  const char *enc_to_path = NULL;
  char *enc_to = NULL;
  int res;

  logInfo ("Called symlink %s->%s\n", from, to);

  if (setjmp (jump_buffer) != 0)
    {
      if (enc_from)
        free ((void *)enc_from);
      if (enc_to)
        free ((void *)enc_to);
      if (enc_from_path)
        free ((void *)enc_from_path);
      if (enc_to_path)
        free ((void *)enc_to_path);
      logErr ("Error in symlink");
      return -errno;
    }

  enc_from_path = encrypt_path_and_filename (from, password);
  enc_from = prefix_path (enc_from_path, root_path);

  enc_to_path = encrypt_path_and_filename (to, password);
  enc_to = prefix_path (enc_to_path, root_path);
  logInfo ("symlink from %s to %s\n", enc_from_path, enc_to_path);

  res = symlink (enc_from, enc_to);
  if (res == -1)
    {
      longjmp (jump_buffer, 1);
    }

  free ((void *)enc_from);
  free ((void *)enc_to);
  free ((void *)enc_from_path);
  free ((void *)enc_to_path);

  return TCFS_SUCCESS;
}

/**
 * @brief Renames a file or a directory.
 *
 * This function is called to rename a file or a directory.
 *
 * @param from Source path.
 * @param to Target path.
 * @param flags Flags for the rename operation.
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_rename (const char *from, const char *to, unsigned int flags)
{
  (void)flags; // FUSE does not use this parameter

  const char *enc_from_path = NULL;
  char *enc_from = NULL;
  const char *enc_to_path = NULL;
  char *enc_to = NULL;
  int res;

  logInfo ("Called rename\n");

  if (setjmp (jump_buffer) != 0)
    {
      if (enc_from)
        free ((void *)enc_from);
      if (enc_to)
        free ((void *)enc_to);
      if (enc_from_path)
        free ((void *)enc_from_path);
      if (enc_to_path)
        free ((void *)enc_to_path);
      logErr ("Error in rename");
      return -errno;
    }

  enc_from_path = encrypt_path_and_filename (from, password);
  enc_from = prefix_path (enc_from_path, root_path);
  enc_to_path = encrypt_path_and_filename (to, password);
  enc_to = prefix_path (enc_to_path, root_path);
  logInfo ("rename from %s to %s\n", enc_from_path, enc_to_path);

  res = rename (enc_from, enc_to);
  if (res == -1)
    longjmp (jump_buffer, 1);

  free ((void *)enc_from);
  free ((void *)enc_from_path);
  free ((void *)enc_to);
  free ((void *)enc_to_path);

  return TCFS_SUCCESS;
}

/**
 * @brief Creates a hard link.
 *
 * This function is called to create a hard link.
 *
 * @param from Source path.
 * @param to Target path.
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_link (const char *from, const char *to)
{
  const char *enc_from_path = NULL;
  char *enc_from = NULL;
  const char *enc_to_path = NULL;
  char *enc_to = NULL;
  int res;

  if (setjmp (jump_buffer) != 0)
    {
      if (enc_from)
        free ((void *)enc_from);
      if (enc_to)
        free ((void *)enc_to);
      if (enc_from_path)
        free ((void *)enc_from_path);
      if (enc_to_path)
        free ((void *)enc_to_path);
      logErr ("Error in rename");
      return -errno;
    }

  logInfo ("Called link\n");

  enc_from_path = encrypt_path_and_filename (from, password);
  enc_from = prefix_path (enc_from_path, root_path);
  enc_to_path = encrypt_path_and_filename (to, password);
  enc_to = prefix_path (enc_to_path, root_path);
  logInfo ("link from %s to %s\n", enc_from, enc_to);

  res = link (enc_from, enc_to);
  if (res == -1)
    {
      longjmp (jump_buffer, 1);
    }

  free ((void *)enc_from);
  free ((void *)enc_from_path);
  free ((void *)enc_to);
  free ((void *)enc_to_path);

  return TCFS_SUCCESS;
}

/**
 * @brief Changes the permissions of a file.
 *
 * This function is called to change the permissions of a file.
 *
 * @param fuse_path The path to the file.
 * @param mode New file mode.
 * @param fi File information.
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_chmod (const char *fuse_path, mode_t mode, struct fuse_file_info *fi)
{
  (void)fi;

  int res;
  const char *enc_fuse_path = NULL;
  const char *path = NULL;

  logInfo ("Called chmod\n");

  if (setjmp (jump_buffer) != 0)
    {
      if (path)
        free ((void *)path);
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
      logErr("Cannot execute chmod");
      return -errno;
    }

  enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);

  res = chmod (path, mode);
  if (res == -1)
    {
      longjmp (jump_buffer, 1);
    }

  free ((void *)path);
  free ((void *)enc_fuse_path);

  return TCFS_SUCCESS;
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
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_chown (const char *fuse_path, uid_t uid, gid_t gid,
            struct fuse_file_info *fi)
{
  (void)fi;

  const char *enc_fuse_path = NULL;
  const char *path = NULL;

  logInfo ("Called chown\n");

  if (setjmp (jump_buffer))
    {
      if (path)
        free ((void *)path);
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
      logErr ("Error in chown");
      return -errno;
    }

  enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);

  int res;
  res = lchown (path, uid, gid);
  if (res == -1)
    longjmp (jump_buffer, 1);

  free ((void *)path);
  free ((void *)enc_fuse_path);

  return TCFS_SUCCESS;
}

/**
 * @brief Truncates or extends the size of a file.
 *
 * This function is called to truncate or extend the size of a file.
 *
 * @param fuse_path The path to the file.
 * @param size New size of the file.
 * @param fi File information.
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_truncate (const char *fuse_path, off_t size, struct fuse_file_info *fi)
{
  (void)fi;
  const char *enc_fuse_path = NULL;
  const char *path = NULL;
  int res;

  logInfo ("Called truncate\n");

  if (setjmp (jump_buffer) != 0)
    {
      if (path)
        free ((void *)path);
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
    }

  enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);

  res = truncate (path, size);
  if (res == -1)
    {
      longjmp (jump_buffer, 1);
    }

  free ((void *)path);
  free ((void *)enc_fuse_path);

  return TCFS_SUCCESS;
}

/**
 * @brief Modify the access and timestamps of a file in the TCFS
 * file system. This function is called when the `utimens` operation is
 * performed on a file.
 *
 * @param fuse_path The path of the encrypted file for which timestamps need to
 * be modified.
 * @param ts An array of two timespec structures containing the new access and
 * modification timestamps.
 * @param fi File information structure provided by FUSE.
 * @return TCFS_SUCCESS on success, negative error code on failure.
 *
 * @details
 * The `tcfs_utimens` function is invoked to modify the access and modification
 * timestamps of a file within the TCFS. It decodes the encrypted file path,
 * translates it into the actual file path on the underlying file system, and
 * then uses the `utimes` function to apply the changes to the file timestamps.
 *
 * @return true on success. On failure, it returns a negative error code
 * representing the type of error encountered.
 *
 */
static int
tcfs_utimens (const char *fuse_path, const struct timespec ts[2],
              struct fuse_file_info *fi)
{
  (void)fi;

  const char *enc_fuse_path = NULL;
  char *path = NULL;
  int res;
  struct timeval tv[2];

  logInfo ("Called utimens\n");

  if (setjmp (jump_buffer) != 0)
    {
      if (path)
        free ((void *)path);
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
      logErr("utimens invalid");
      return -errno;
    }

  enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);

  tv[0].tv_sec = ts[0].tv_sec;
  tv[0].tv_usec = ts[0].tv_nsec / 1000;
  tv[1].tv_sec = ts[1].tv_sec;
  tv[1].tv_usec = ts[1].tv_nsec / 1000;

  res = utimes (path, tv);
  if (res == -1)
    {
      longjmp (jump_buffer, 1);
    }

  free ((void *)path);
  free ((void *)enc_fuse_path);

  return TCFS_SUCCESS;
}

/**
 * @brief This function is called to open a file.
 *
 * @param fuse_path The path to the file.
 * @param fi File information.
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_open (const char *fuse_path, struct fuse_file_info *fi)
{
  const char *enc_fuse_path = NULL;
  char *path = NULL;
  int res = 0;

  logInfo ("Called open\n");

  if (setjmp (jump_buffer) != 0)
    {
      if (path)
        free ((void *)path);
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
      logErr("cannot open");
      return -errno;
    }

  enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);
  logInfo ("\topen on %s\n", path);

  res = open (path, fi->flags);
  if (res == -1)
    {
      longjmp (jump_buffer, 1);
    }

  close (res);
  free ((void *)path);
  free ((void *)enc_fuse_path);

  return TCFS_SUCCESS;
}

/**
 * @brief Get the size of a file in the TCFS file system.
 *
 * This function is called when the `getattr` operation is performed on a file
 * in the TCFS to obtain file attributes.
 *
 * @param fuse_path The path of the encrypted file within the TCFS.
 * @param stbuf Buffer to store the file attributes, including the file size.
 * @param fi File information provided by FUSE, which may be used to obtain
 * additional details about the file if needed.
 *
 * @details
 * The `file_size` function is invoked to retrieve the size of a file
 * within the TCFS. It decodes the encrypted file path, translates it into the
 * actual file path on the underlying file system, and then uses the `getattr`
 * function to obtain the file attributes, including the file size.
 *
 *
 * @return true on success. On failure, it returns a negative error code
 * representing the type of error encountered.
 *
 * @note
 * - The correct functioning of this function is essential for providing
 * accurate information about the file size.
 *
 * @warning
 * - Ensure that the function correctly translates the encrypted file path into
 * the actual file path on the underlying file system.
 */
static inline int
file_size (FILE *file)
{
  struct stat st;

  if (fstat (fileno (file), &st) == 0)
    return st.st_size;

  return -ERR_inval_file_size;
}

/**
 * @brief Reads encrypted data from an open file and decrypts it.
 *
 * This function is called to read encrypted data from an open file and decrypt it. It uses AES decryption.
 *
 * @param fuse_path The path to the file.
 * @param buf Buffer to fill with decrypted data.
 * @param size Number of bytes to read.
 * @param offset Offset within the file.
 * @param fi File information.
 *
 * @return The number of bytes read, or a negative error code on failure.
 *
 * @note This function uses OpenSSL's RAND_bytes function to generate a random IV if the file is new.
 * It retrieves the file key and the IV from the file's extended attributes, decrypts the data, and writes the decrypted data to the buffer.
 * The function uses OpenSSL's EVP API for decryption.
 * It also sets up error handling using setjmp.
 *
 * @warning This function allocates memory for various data including the IV, the file key, and the decrypted data.
 * It is the responsibility of this function to free this memory before it returns.
 */
static int
tcfs_read (const char *fuse_path, char *buf, size_t size, off_t offset,
           struct fuse_file_info *fi)
{
  (void)size;
  (void)fi;
  (void) offset; //TODO: use offset;

  FILE *path_ptr = NULL;
  char *path;
  const char *enc_fuse_path = NULL;
  char *size_key_char = NULL;
  ssize_t size_key;
  unsigned char *encrypted_key = NULL;
  unsigned char *decrypted_key = NULL;
  unsigned char *iv = NULL;
  unsigned char *plaintext = NULL;
  char err_string[80];

  logInfo ("Calling read\n");

  if (setjmp (jump_buffer) != 0)
    {
      if (path_ptr)
        fclose (path_ptr);
      if (path)
        free ((void *)path);
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
      if (encrypted_key)
        free ((void *)encrypted_key);
      if (decrypted_key)
        free ((void *)decrypted_key);
      logErr (err_string);
      return -errno;
    }

  enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);
  logInfo ("\tread on %s\n", path);

  path_ptr = fopen (path, "r");

  // Get key size
  size_key_char = malloc (sizeof (char) * 20);
  if (tcfs_getxattr (fuse_path, "user.key_len", size_key_char, 20) == -1)
    {
      strcpy (err_string, "Error in read,, could not get file key size");
      longjmp (jump_buffer, 1);
    }
  size_key = strtol (size_key_char, NULL, 10);

  // Retrive the file key
  encrypted_key = malloc ((size_key + 1) * sizeof (char));
  encrypted_key[size_key] = '\0';
  if (tcfs_getxattr (fuse_path, "user.key", (char *)encrypted_key, size_key)
      == -1)
    {
      strcpy (
          err_string,
          "Error in read, could not get encrypted key for file in tcfs_read");
      longjmp (jump_buffer, 1);
    }

  //Retrieve the IV
  iv = malloc ((IV_SIZE * sizeof (char )));
  if (tcfs_getxattr (fuse_path, IV_ATTR_NAME, (char *)iv, IV_SIZE) < 0){
      strcpy (err_string, "Error in read, could not get the IV");
      longjmp (jump_buffer, 1);
    }

  // Decrypt the file key
  decrypted_key = decrypt_string (encrypted_key, (const char *)password);

  // Decrypt
  if (do_crypt (DECRYPT, path_ptr, &plaintext, 0, (unsigned char *)decrypted_key, iv) == false)
    {
      strcpy (err_string, "Error in read, do_crypt cannot decrypt file");
      longjmp (jump_buffer, 1);
    }

  // Copy the decrypted text into the buffer.
  size_t plaintext_len = strlen((const char *)plaintext) + 1;
  if (plaintext_len > size) {
      strcpy(err_string, "Error: Buffer is not large enough for the decrypted data.\n");
      errno = ERR_inval_read_buf_size;
      longjmp (jump_buffer, 1);
    }

  memcpy (buf, plaintext, plaintext_len);

  fclose (path_ptr);
  free ((void *)path);
  free ((void *)enc_fuse_path);
  free ((void *)encrypted_key);
  free ((void *)decrypted_key);

  return (int)plaintext_len;
}

/**
 * @brief Writes encrypted data to an open file.
 *
 * This function is called to write encrypted data to an open file. It uses AES encryption.
 *
 * @param fuse_path The path to the file.
 * @param buf Data to write.
 * @param size Number of bytes to write.
 * @param offset Offset within the file.
 * @param fi File information.
 *
 * @return The number of bytes written, or a negative error code on failure.
 *
 * @note This function uses OpenSSL's RAND_bytes function to generate a random IV if the file is new.
 * It retrieves the file key and the IV from the file's extended attributes, decrypts the file key,
 * encrypts the data, and writes the encrypted data to the file.
 * The function uses OpenSSL's EVP API for encryption.
 * It also sets up error handling using setjmp.
 *
 * @warning This function allocates memory for various data including the IV, the file key, and the encrypted data.
 * It is the responsibility of this function to free this memory before it returns.
 */
static int
tcfs_write (const char *fuse_path, const char *buf, size_t size, off_t offset,
            struct fuse_file_info *fi)
{
  (void)fi;
  (void) offset; //TODO: use offset;

  logInfo ("Called write\n");

  FILE *path_ptr = NULL;
  char *path;
  const char *enc_fuse_path = NULL;
  char *size_key_char = NULL;
  unsigned char *encrypted_key = NULL;
  unsigned char *decrypted_key = NULL;
  unsigned char *iv = NULL;
  unsigned char *enc_buf = NULL;
  char err_string[80] = "\0";
  int encrypted_len;

  if (setjmp (jump_buffer) != 0)
    {
      if (path_ptr)
        fclose (path_ptr);
      if (path)
        free (path);
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
      if (size_key_char)
        free ((void *)size_key_char);
      if (encrypted_key)
        free ((void *)encrypted_key);
      if (decrypted_key)
        free ((void *)decrypted_key);
      if (iv)
        free ((void *)iv);
      if (enc_buf)
        free((void *) enc_buf);
      logErr (err_string);
      return -errno;
    }

  enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);
  logInfo ("\twrite on %s\n", path);

  path_ptr = fopen (path, "a+");
  if (path_ptr == NULL) {
      strcpy (err_string, "Read error, could not open file");
      longjmp (jump_buffer, 1);
    }

  // Get the key size
  size_key_char = malloc (sizeof (char) * 20);
  if (tcfs_getxattr (fuse_path, "user.key_len", size_key_char, 20) == -1)
    {
      strcpy (err_string, "Error in write, could not get file key size");
      longjmp (jump_buffer, 1);
    }
  ssize_t size_key = strtol (size_key_char, NULL, 10);

  // Retrieve the file key
  encrypted_key = malloc (sizeof (unsigned char) * (size_key + 1));
  encrypted_key[size_key] = '\0';
  if (tcfs_getxattr (fuse_path, "user.key", (char *)encrypted_key, size_key)
      == -1)
    {
      strcpy (err_string, "Error in write, could not get file encrypted key");
      longjmp (jump_buffer, 1);
    }

  // Decrypt the file key
  decrypted_key = decrypt_string (encrypted_key, password);

  // Retrive the IV or generate a new one if the file is new
  iv = malloc ((IV_SIZE * sizeof (char )));
  if (tcfs_getxattr (fuse_path, IV_ATTR_NAME, (char *)iv, IV_SIZE) < 0){
      iv = generate_iv();
      logInfo ("IV generated");
      int set_iv = tcfs_setxattr(fuse_path, IV_ATTR_NAME, (const char *)iv, IV_SIZE, 0);
      if (set_iv < 0){
          strcpy (err_string, "Error in write, cannot set the IV");
          longjmp (jump_buffer, 1);
        }
    }

  // Something went terribly wrong if this is the case.
  if (path_ptr == NULL)
    {
      strcpy (err_string, "Error in write, cannot create new files");
      longjmp (jump_buffer, 1);
    }

  // Encrypt
  encrypted_len = do_crypt (ENCRYPT, path_ptr, (unsigned char **)&buf, (int)size, (unsigned char *)decrypted_key, iv);
  if (encrypted_len == false)
    {
      strcpy (err_string, "Error in write, cannot cypher file");
      longjmp (jump_buffer, 1);
    }

  fclose (path_ptr);
  free ((void *)path);
  free ((void *)enc_fuse_path);
  free ((void *)size_key_char);
  free ((void *)encrypted_key);
  free ((void *)decrypted_key);
  free ((void *) enc_buf);

  return encrypted_len;
}

/**
 * @brief Get file system statistics.
 *
 * This function is called when the `statfs` operation is performed to obtain
 * statistics about the TCFS file system.
 *
 * @param fuse_path The path of the file system within the TCFS.
 * @param stbuf Buffer to store file system statistics.
 * @return TCFS_SUCCESS on success, negative error code on failure.
 *
 * @details
 * The `tcfs_statfs` function is invoked to retrieve statistics about the TCFS
 * file system. It may include information such as the total size, free space,
 * and available space.
 *
 * @return true on success. On failure, it returns a negative error code
 * representing the type of error encountered.
 *
 * @note
 * - The function is essential for providing information about the overall
 * status of the TCFS file system.
 *
 * @warning
 * - The accuracy of the reported statistics is crucial for applications that
 * rely on file system information.
 */
static int
tcfs_statfs (const char *fuse_path, struct statvfs *stbuf)
{
  char *path = NULL;
  int res;

  logInfo ("Called statfs\n");

  if (setjmp (jump_buffer) != 0)
    {
      if (path)
        free ((void *)path);
      logErr ("Error in statfs");
      return -errno;
    }

  path = prefix_path (fuse_path, root_path);

  res = statvfs (path, stbuf);
  if (res == -1)
    longjmp (jump_buffer, 1);

  free ((void *)path);

  return TCFS_SUCCESS;
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
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_setxattr (const char *fuse_path, const char *name, const char *value,
               size_t size, int flags)
{
  const char *enc_fuse_path = NULL;
  const char *path = NULL;
  int res = 1;

  logInfo ("\tsetxattr encrypt_path %s settin%s:%s\n", path, name, value);

  if (setjmp (jump_buffer) != 0)
    {
      if (path)
        free ((void *)path);
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
      logErr ("Error in setxattr");
      return -errno;
    }

  enc_fuse_path = encrypt_path (fuse_path, password);
  path = prefix_path (enc_fuse_path, root_path);

  res = lsetxattr (path, name, value, size, flags);
  if (res == -1)
    longjmp (jump_buffer, 1);

  free ((void *)path);
  free ((void *)enc_fuse_path);

  return TCFS_SUCCESS;
}

/**
 * @brief Create and open a file.
 *
 * This function is called when a new file is created in the TCFS file system.
 *
 * @param fuse_path The path of the file within the TCFS.
 * @param mode The mode of the file, specifying permissions and other
 * attributes.
 * @param fi File information containing flags and an open file handle.
 * @return TCFS_SUCCESS on success, negative error code on failure.
 *
 * @details
 * The `create` function is invoked when a new file is created in the TCFS file
 * system. It is responsible for setting up the necessary data structures,
 * allocating resources, and opening the file for subsequent read and write
 * operations.
 *
 *
 * @note
 * - The function must create the file and return an open file handle in the
 * `fi` structure.
 * - Ensure proper handling of file permissions, resource allocation, and any
 * other relevant attributes.
 *
 * @warning
 * - Verify that the function correctly handles errors
 */
static int
tcfs_create (const char *fuse_path, mode_t mode, struct fuse_file_info *fi)
{
  (void)fi;
  (void)mode;

  const char *enc_fuse_path = NULL;
  const char *fullpath = NULL;
  unsigned char *key = NULL;
  int encrypted_key_len = 0;
  unsigned char *encrypted_key = NULL;
  char encrypted_key_len_char[20];
  FILE *res = NULL;
  char err_string[80] = "\0";

  logInfo ("Called create on %s\n", fuse_path);

  if (setjmp (jump_buffer) != 0)
    {
      if (fullpath)
        free ((void *)fullpath);
      if (enc_fuse_path)
        free ((void *)enc_fuse_path);
      if (encrypted_key)
        free ((void *)encrypted_key);
      if (key)
        free ((void *)key);
      if (res)
        fclose (res);
      logErr (err_string);
      return -errno;
    }

  enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  fullpath = prefix_path (enc_fuse_path, root_path);
  logInfo ("\tcreating %s\n", fullpath);

  res = fopen (fullpath, "w");
  if (res == NULL)
    {
      strcpy (err_string, "Error in create, cannot open path");
      longjmp (jump_buffer, 0);
    }

  // Flag file as encrypted
  if (tcfs_setxattr (fuse_path, "user.encrypted", "true", 4, 0)
      != TCFS_SUCCESS)
    {
      strcpy (err_string,
              "Error in create, cannot set file ecrypted attribute");
      longjmp (jump_buffer, 1);
    }

  // Generate and set a new encrypted key for the file
  key = malloc (sizeof (unsigned char) * 33);
  key[32] = '\0';
  generate_key (key);

  if (key == NULL)
    {
      strcpy (err_string, "Error in create, cannot generate file key");
      longjmp (jump_buffer, 1);
    }
  /*if (is_valid_key (key) == false)
    {
      perror ("Generated key size invalid\n");
      return -1;
    }This should not be needed anymore*/

  // Encrypt the generated key
  encrypted_key = encrypt_string (key, password, &encrypted_key_len);

  // Set the file key
  if (tcfs_setxattr (fuse_path, "user.key", (const char *)encrypted_key,
                     encrypted_key_len, 0)
      != 0)
    {
      strcpy (err_string, "Error in sreate, cannot set key xattr");
      longjmp (jump_buffer, 1);
    }
  // Set key size
  snprintf (encrypted_key_len_char, sizeof (encrypted_key_len_char), "%d",
            encrypted_key_len);
  if (tcfs_setxattr (fuse_path, "user.key_len", encrypted_key_len_char,
                     sizeof (encrypted_key_len_char), 0)
      != TCFS_SUCCESS)
    {
      strcpy (err_string, "Error in create, cannot set key_len xattr");
      longjmp (jump_buffer, 1);
    }

  free ((void *)fullpath);
  free ((void *)enc_fuse_path);
  free ((void *)encrypted_key);
  free ((void *)key);
  fclose (res);

  return TCFS_SUCCESS;
}

/**
 * @brief Releases an open file.
 *
 * This function is called to release an open file.
 *
 * @param fuse_path The path to the file.
 * @param fi File information.
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_release (const char *fuse_path, struct fuse_file_info *fi)
{
  (void) fuse_path;
  (void) fi;
  /*const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  logMessage ("release %s\n", path);

  //Close the file
  int res = close (fi->fh);
  if (res == -1)
    {
      perror ("Release error");
      return -errno;
    }

  //Free the path
  free ((void *)path);
  free ((void *)enc_fuse_path);*/

  return TCFS_SUCCESS;
}

/**
 * @brief Synchronizes file contents.
 *
 * This function is called to synchronize file contents.
 *
 * @param fuse_path The path to the file.
 * @param datasync Flag indicating whether to sync only data.
 * @param fi File information.
 * @return true on success, a negative error code on failure.
 */
static int
tcfs_fsync (const char *fuse_path, int isdatasync, struct fuse_file_info *fi)
{
  /* Get the real path */
  const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  logInfo ("\tfsync %s\n", path);

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

  return TCFS_SUCCESS;
}

/**
 * @brief Get extended attribute data.
 *
 * This function is called to retrieve the value of an extended attribute for a
 * specified file or directory.
 *
 * @param fuse_path The path of the file or directory within the TCFS.
 * @param name The name of the extended attribute to retrieve.
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
 * @return On success, the function returns the extended attribute value.
 * On failure, it returns a negative error code representing the type of
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

  logInfo ("Called getxattr on %s name:%s size:%zu\n", path, name, size);

  int res = (int)lgetxattr (path, name, value, size);
  if (res == -1)
    {
      logErr ("Could not get xattr for file");
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
  logInfo ("Called listxattr\n");
  const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  logInfo ("\tlistxattr %s\n", path);

  ssize_t res = llistxattr (path, list, size);
  if (res == -1L)
    {
      logErr ("listxattr error");
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
 * @return TCFS_SUCCESS on success, negative error code on failure.
 *
 * @details
 * The `removexattr` function is invoked to remove the specified extended
 * attribute associated with a file or directory within the TCFS file system.
 *
 * @return On success, the function returns TCFS_SUCCESS. On failure, it
 * returns a negative error code representing the type of error encountered.
 *
 * @note
 * - The function must ensure the proper removal of the specified extended
 * attribute.
 * - Implement appropriate checks to handle different scenarios and edge cases.
 */
static int
tcfs_removexattr (const char *fuse_path, const char *name)
{
  logInfo ("Called removexattr\n");
  const char *enc_fuse_path = encrypt_path_and_filename (fuse_path, password);
  const char *path = prefix_path (enc_fuse_path, root_path);
  logInfo ("\tremovexattr %s\n", path);

  int res = lremovexattr (path, name);
  if (res == -1)
    {
      logErr ("removexattr error");
      return -errno;
    }
  return TCFS_SUCCESS;
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
 * @brief Main entry point for TCFS.
 *
 * @return fuse_main result on success, error code on failure.
 */

int main(int argc, char *argv[]) {
  struct config *conf = malloc (sizeof(struct config));
  char *config_file = NULL;
  int c;
  int fuse_result;

  //Change file permissions
  umask (0);

  config_file = strdup(DEFAULT_CONFIG_FILE);
  //Read if a different config file location is set
  while ((c = getopt(argc, argv, "c:")) != -1) {
      switch (c) {
        case 'c':
          config_file = strdup(optarg);
          break;
        case '?':
          if (optopt == 'c')
            logErr("Option -%c requires an argument.\n", optopt);
          else
            logErr("Unknown option `-%c'.\n", optopt);
          return 1;
        default:
          abort();
        }
    }

  // Load config
  if (parse_config(config_file, conf) != true) {
      logErr("Cannot load config from %s\n", config_file);
      free(config_file);
      return EXIT_FAILURE;
    }

  // Set debug level
  set_debug_level(conf->debug);

  // Set log_to_console
  enable_console_logging (conf->log_to_console);

  // Set the root path
  root_path = conf->source;

  // Check if submitted key is valid
  if (is_valid_key ((unsigned char *)conf->password) == TCFS_SUCCESS)
    {
      logErr("Inserted key not valid\n");
      return -ERR_inval_key;
    }

  // Load arguments in fuse
  struct fuse_args args_fuse = FUSE_ARGS_INIT (0, NULL);
  fuse_opt_add_arg (&args_fuse, "./tcfs");
  fuse_opt_add_arg (&args_fuse, conf->destination);
  fuse_opt_add_arg (&args_fuse,conf->params);

  // Save the password. WARN: This is already deprecated, the next update will handle key with Keyutils
  password = conf->password;

  fuse_result = fuse_main (args_fuse.argc, args_fuse.argv, &tcfs_oper, NULL);
  if (fuse_result != 0){
      logWarn("Fuse stopped with an error");
      return -EXIT_FAILURE;
    }
  else{
      logWarn("Fuse exited");
    }

  // Free the memory used by the configuration
  free(config_file);
  free(conf->source);
  free(conf->destination);
  free(conf->key_id);
  free(conf);

  return fuse_result;
}
