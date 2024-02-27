#include "common_utils.h"

/**
 * @internal @_file
 * @file common_utils.c
 * @brief File containing the common functions used by different algorithms in this library
 */

/**
 * @internal @_var
 * @var jump_buffer
 * @brief Buffer for storing the environment for `setjmp` and `longjmp`.
 */
extern jmp_buf jump_buffer;

/**
 * @internal @_func
 * @brief
 * This function retrieves the latest OpenSSL error message.
 *
 * @return
 * Returns a string containing the error message.
 * The caller is responsible for freeing this string.
 *
 * @note
 * This function uses OpenSSL's BIO API to get the error message.
 */
extern char *
getOpenSSLError (void)
{
  BIO *bio = BIO_new (BIO_s_mem ());
  ERR_print_errors (bio);
  char *buf;
  size_t len = BIO_get_mem_data (bio, &buf);
  char *ret = (char *)malloc ((len + 1) * sizeof (char));
  memcpy (ret, buf, len);
  ret[len] = '\0';
  BIO_free (bio);
  return ret;
}

/**
 * @internal @_func
 * @brief
 * This function handles errors by logging the latest OpenSSL error message and
 * performing a non-local jump.
 *
 * @note
 * This function uses `longjmp` to jump to the location stored in
 * `jump_buffer`. This means that the function where `setjmp` was called with
 * `jump_buffer` will return with the value 1. It's important to ensure that
 * `setjmp` has been called before this function is used.
 */
extern void
handleErrors (void)
{
  char *error = getOpenSSLError ();
  logErr ("openssl: %s", error);
  if (error)
    free (error);
  longjmp (jump_buffer, 1);
}