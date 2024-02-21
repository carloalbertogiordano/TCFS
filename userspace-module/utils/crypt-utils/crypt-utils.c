/**
 * @file crypt-utils.c
 * @brief Implementation file for cryptographic utility functions.
 *
 * This file contains the implementation of various cryptographic utility
 * functions, including AES encryption and decryption, key generation,
 * entropy checks, and path encryption/decryption.
 *
 * @author
 * By Carlo Alberto Giordnano \n
 * Created 18/10/23 by [Carlo Alberto Giordano] \n
 */

#include "crypt-utils.h"
#include "../debug_utils/debug_helper.h"
#include "../tcfs_utils/tcfs_utils.h"

/**
 * @internal @_def
 * @def TAG_LEN
 * @brief The length of the authentication tag.
 */
#define TAG_LEN 16

/**
 * @internal @_var
 * @var jump_buffer
 * @brief Buffer for storing the environment for `setjmp` and `longjmp`.
 */
jmp_buf jump_buffer;

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
static char *
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
static void
handleErrors (void)
{
  char *error = getOpenSSLError ();
  logErr ("openssl: %s", error);
  if (error)
    free (error);
  longjmp (jump_buffer, 1);
}

/**
 * @internal @_func
 *
 * @brief
 * This function encrypts a file using AES 256 GCM.
 *
 * @param fp  The input file.
 * @param plaintext  The plaintext to be encrypted.
 * @param plaintext_len  The length of the plaintext.
 * @param key  The AES 256 key.
 * @param iv  The initialization vector.
 *
 * @return
 * Returns the length of the encrypted ciphertext.
 * In case of an error, it prints an error message and returns -1.
 *
 * @note
 * This function encrypts using AES 256 GCM.
 * The function encrypts the plaintext and writes the ciphertext and the
 * authentication tag to the file. The function uses OpenSSL's EVP API for
 * encryption. For each block the function writes: block_size|block|TAG. The
 * decrypt_file_gcm depends on this behaviour.
 */
static int
encrypt_file_gcm (FILE *fp, unsigned char *plaintext, int plaintext_len,
                  unsigned char *key, unsigned char *iv)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  unsigned char *ciphertext = NULL;
  unsigned char tag[TAG_LEN];

  if (setjmp (jump_buffer))
    {
      logErr ("An error occurred in encrypt_file_gcm! Freeing resources...\n");
      EVP_CIPHER_CTX_free (ctx);
      if (ciphertext)
        free (ciphertext);
      return false;
    }

  if (!(ctx = EVP_CIPHER_CTX_new ()))
    handleErrors ();

  if (1 != EVP_EncryptInit_ex (ctx, EVP_aes_256_gcm (), NULL, key, iv))
    handleErrors ();

  ciphertext = (unsigned char *)malloc (
      plaintext_len + EVP_CIPHER_block_size (EVP_aes_256_gcm ()));
  if (!ciphertext)
    handleErrors ();

  if (1 != EVP_EncryptUpdate (ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors ();
  ciphertext_len = len;

  if (1 != EVP_EncryptFinal_ex (ctx, ciphertext + len, &len))
    handleErrors ();
  ciphertext_len += len;

  if (1 != EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag))
    handleErrors ();

  fwrite (&ciphertext_len, sizeof (int), 1, fp);

  if (fwrite (ciphertext, sizeof (unsigned char), ciphertext_len, fp)
      != (unsigned long)ciphertext_len)
    {
      handleErrors ();
    }

  if (fwrite (tag, sizeof (unsigned char), TAG_LEN, fp)
      != (unsigned long)TAG_LEN)
    {
      handleErrors ();
    }

  EVP_CIPHER_CTX_free (ctx);

  free (ciphertext);
  return ciphertext_len;
}

/**
 * @internal @_func
 *
 * @brief
 * This function decrypts a file using AES 256 GCM.
 *
 * @param fp  The input file.
 * @param key  The AES 256 key.
 * @param iv  The initialization vector.
 * @param plaintext  The decrypted text will be written here.
 *
 * @return
 * Returns the length of the decrypted plaintext.
 * In case of an error, it prints an error message and returns false.
 *
 * @note
 * This function decrypts using AES 256 GCM.
 * The function reads the ciphertext and the authentication tag from the file,
 * then decrypts the ciphertext and writes the plaintext to the provided
 * pointer. The function expects each block to be written as:
 * block_size|block|TAG
 *
 * @warning
 * The plaintext variable will be allocated by this function,
 * it is the responsibility of the caller to free it.
 */
static int
decrypt_file_gcm (FILE *fp, unsigned char *key, unsigned char *iv,
                  unsigned char **plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len = 0;
  unsigned char *ciphertext = NULL;
  unsigned char tag[TAG_LEN];

  if (setjmp (jump_buffer))
    {
      logErr ("An error occurred in decrypt_file_gcm! Freeing resources...\n");
      EVP_CIPHER_CTX_free (ctx);
      if (ciphertext)
        free (ciphertext);
      return false;
    }

  fseek (fp, 0, SEEK_END);
  long fsize = ftell (fp);
  fseek (fp, 0, SEEK_SET); // same as rewind(f);

  *plaintext = NULL;

  while (ftell (fp) < fsize)
    {
      int ciphertext_len;
      fread (&ciphertext_len, sizeof (int), 1, fp);

      ciphertext = malloc (ciphertext_len);
      if (!ciphertext)
        handleErrors ();

      fread (ciphertext, sizeof (unsigned char), ciphertext_len, fp);

      fread (tag, sizeof (unsigned char), TAG_LEN,
             fp); // Read the tag from the file

      if (!(ctx = EVP_CIPHER_CTX_new ()))
        handleErrors ();

      if (1 != EVP_DecryptInit_ex (ctx, EVP_aes_256_gcm (), NULL, key, iv))
        handleErrors ();

      if (!EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag))
        handleErrors ();

      *plaintext = realloc (*plaintext, plaintext_len + ciphertext_len);
      if (!*plaintext)
        handleErrors ();

      if (1
          != EVP_DecryptUpdate (ctx, *plaintext + plaintext_len, &len,
                                ciphertext, ciphertext_len))
        handleErrors ();
      plaintext_len += len;

      if (1 != EVP_DecryptFinal_ex (ctx, *plaintext + plaintext_len, &len))
        handleErrors ();
      plaintext_len += len;

      EVP_CIPHER_CTX_free (ctx);

      free (ciphertext);
    }

  return plaintext_len;
}

/**
 * @brief
 * High-level function for performing AES encryption on FILE pointers.
 * Uses OpenSSL libcrypto EVP API.
 *
 * @param mode  Defines if the action to be performed on the input file should
 * be encryption or decryption.
 * @param fp  The input file.
 * @param text  The text to be encrypted and write to the file or where the
 * decrypted text will be written
 * @param len  The length of the text. Only needed in ENCRYPT mode
 * @param key  The AES 256 key.
 * @param iv  The initialization vector.
 *
 * @return
 * Returns the result of the `encrypt_file_gcm` function if the mode is
 * ENCRYPT, otherwise returns the result of the `decrypt_file_gcm` function if
 * the mode is DECRYPT. In case of an error, it prints an error message and
 * returns false.
 *
 * @note This function encrypts using AES 256 CTX.
 * @warning If the mode is DECRYPT the text variable will be allocated by this
 * function, it is responsibility of the caller to free it
 */
extern int
do_crypt (int mode, FILE *fp, unsigned char **text, int len,
          unsigned char *key, unsigned char *iv)
{
  if (mode == DECRYPT)
    {
      return decrypt_file_gcm (fp, key, iv, text);
    }
  else if (mode == ENCRYPT)
    {
      return encrypt_file_gcm (fp, *text, len, key, iv);
    }
  logErr ("Error in do_crypt, undefined mode selected");
  return false;
}

/**
 * @brief Verify if there is enough entropy in the system to generate a key
 * @return A value greater than 0 corresponding to the entropy level, if an
 * error occurs false is returned
 * @note This function evaluates the entropy by checking the
 * /proc/sys/kernel/random/entropy_avail file. \see man page 4 for random
 * */
int
check_entropy (void)
{
  FILE *entropy_file = fopen ("/proc/sys/kernel/random/entropy_avail", "r");
  if (entropy_file == NULL)
    {
      logErr ("Err: Cannot open entropy file");
      return false;
    }

  int entropy_value;
  if (fscanf (entropy_file, "%d", &entropy_value) != true)
    {
      logErr ("Err: Cannot estimate entropy");
      fclose (entropy_file);
      return false;
    }

  fclose (entropy_file);
  return entropy_value;
}

/**
 * @brief Force new entropy in /dev/urandom
 * @return void
 * @warning Very dangerous, if this fails an error will be printed and the
 * program will exit with EXIT_FAILURE
 * */
void
add_entropy (void)
{
  FILE *urandom = fopen ("/dev/urandom", "rb");
  if (urandom == NULL)
    {
      logErr ("Err: Cannot open /dev/urandom");
      exit (EXIT_FAILURE);
    }

  unsigned char random_data[32];
  size_t bytes_read = fread (random_data, 1, sizeof (random_data), urandom);
  fclose (urandom);

  if (bytes_read != sizeof (random_data))
    {
      logErr ("Cannot read entropy data");
      exit (EXIT_FAILURE);
    }

  // Use random data to fill up entropy
  RAND_add (random_data, sizeof (random_data),
            0.5); // 0.5 is an arbitrary weight

  logDebug ("Entropy added successfully!\n");
}

/**
 * @brief Generate a new AES 256 key for a file
 * @param destination Pointer to the string in which the
 * generated key will be saved. If an error occurs it will be set to NULL
 * @return void
 * */
void
generate_key (unsigned char *destination)
{
  logDebug ("Generating a new key...");

  // Why? Because if we try to create a large number of files there might not
  // be enough random bytes in the system to generate a key
  for (int i = 0; i < 10; i++)
    {
      int entropy = check_entropy ();
      if (entropy < 128)
        {
          logWarn ("Not enough entropy, creating some...");
          add_entropy ();
        }

      if (RAND_bytes (destination, 32) != true)
        {
          logErr ("Cannot generate key");
          destination = NULL;
        }

      if (strlen ((const char *)destination) == 32)
        break;
    }

  if (is_valid_key (destination) == false)
    {
      logErr ("ERR: Generated key is invalid\n");
      destination = NULL;
    }
}

/**
 * @brief Encrypt the *plaintext string using a AES 256 key
 * @param plaintext This is the string to encrypt
 * @param key The AES 256 KEY
 * @param encrypted_len This will be set to the encrypted string length
 * @return unsigned char *  The encrypted string will be allocated and then
 * returned
 * @note After the use remember to free the result
 * */
unsigned char *
encrypt_string (unsigned char *plaintext, const char *key,
                int *encrypted_key_len)
{
  EVP_CIPHER_CTX *ctx;
  const EVP_CIPHER *cipher = EVP_aes_256_cbc ();
  unsigned char iv[AES_BLOCK_SIZE];
  memset (iv, 0, AES_BLOCK_SIZE);

  ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    {
      return NULL;
    }

  EVP_EncryptInit_ex (ctx, cipher, NULL, (const unsigned char *)key, iv);

  size_t plaintext_len = strlen ((const char *)plaintext);
  unsigned char ciphertext[plaintext_len + AES_BLOCK_SIZE];
  memset (ciphertext, 0, sizeof (ciphertext));

  int len, total_len = 0;
  EVP_EncryptUpdate (ctx, ciphertext, &len, plaintext, (int)plaintext_len);
  total_len += len;
  EVP_EncryptFinal_ex (ctx, ciphertext + total_len, &len);
  total_len += len;
  EVP_CIPHER_CTX_free (ctx);

  unsigned char *encoded_string = malloc (total_len * 2 + 1);
  if (!encoded_string)
    {
      logErr ("Cannot allocate memory for encrypt_string encoded_string");
      return NULL;
    }

  for (int i = 0; i < total_len; i++)
    {
      sprintf ((char *)&encoded_string[i * 2], "%02x", ciphertext[i]);
    }
  encoded_string[total_len * 2] = '\0';

  *encrypted_key_len = total_len * 2;
  return encoded_string;
}

/**
 * @brief Decrypt the *ciphertext string using a AES 256 key
 * @param ciphertext  This is the string to decrypt in HEX format
 * @param key The AES 256 KEY
 * @return unsigned char *  The plaintext string will be allocated and then
 * returned
 * @note After the use remember to free the result
 * */
unsigned char *
decrypt_string (unsigned char *ciphertext, const char *key)
{
  EVP_CIPHER_CTX *ctx;
  const EVP_CIPHER *cipher = EVP_aes_256_cbc ();
  unsigned char iv[AES_BLOCK_SIZE];
  memset (iv, 0, AES_BLOCK_SIZE);

  ctx = EVP_CIPHER_CTX_new ();
  EVP_DecryptInit_ex (ctx, cipher, NULL, (const unsigned char *)key, iv);

  size_t ciphertext_len = strlen ((const char *)ciphertext) / 2;
  unsigned char *decoded_ciphertext = malloc (ciphertext_len);

  if (!decoded_ciphertext)
    {
      logErr ("Cannot allocate memory for decrypt_string decoded_ciphertext");
      return NULL;
    }

  for (size_t i = 0; i < ciphertext_len; i++)
    {
      char hex[3]
          = { (char)ciphertext[i * 2], (char)ciphertext[i * 2 + 1], '\0' };
      char *endptr;
      unsigned long byte = strtoul (hex, &endptr, 16);

      if (*endptr != '\0' || byte > UCHAR_MAX)
        {
          logErr ("decrypt string error");
          free ((void *)decoded_ciphertext);
          return NULL;
        }
      decoded_ciphertext[i] = byte;
    }

  unsigned char plaintext[ciphertext_len + AES_BLOCK_SIZE + 1];
  memset (plaintext, 0, sizeof (plaintext));

  int len;
  EVP_DecryptUpdate (ctx, plaintext, &len, decoded_ciphertext,
                     (int)ciphertext_len);
  int padding_len;
  EVP_DecryptFinal_ex (ctx, plaintext + len, &padding_len);
  EVP_CIPHER_CTX_free (ctx);

  unsigned char *decrypted_string
      = (unsigned char *)malloc (len + padding_len + 1);

  if (!decrypted_string)
    {
      logErr ("Cannot allocate memory for decrypt_string decrypted_string");
      return NULL;
    }

  memcpy (decrypted_string, plaintext, len + padding_len);
  decrypted_string[len + padding_len] = '\0';

  free (decoded_ciphertext);

  return decrypted_string;
}

/**
 * @brief Check if a given key is valid
 * @param key The key to validate
 * @return \ret
 * @note This function only checks for key length
 * */
int
is_valid_key (const unsigned char *key)
{
  char str[33];
  memcpy (str, key, 32);
  str[32] = '\0';
  size_t key_length = strlen (str);
  return key_length != 32 ? false : true;
}

const char *
encrypt_file_name_with_hex (const char *file, const char *key)
{
  int len = -1;
  return (const char *)encrypt_string ((unsigned char *)string_to_hex (file),
                                       key, &len);
}

const char *
decrypt_file_name_with_hex (const char *enc_file, const char *key)
{
  return (const char *)hex_to_string (
      (const char *)decrypt_string ((unsigned char *)enc_file, key));
}

/**
 * @brief Encrypts each part of the given path using a specified key.
 * @param path The input path to be encrypted.
 * @param key The encryption key.
 * @return A dynamically allocated string containing the encrypted path.
 *         It is the responsibility of the caller to free this memory.
 */
const char *
encrypt_path (const char *path, const char *key)
{
  char *result = NULL;
  char *token, *saveptr;

  // Check if the path is ".", ".."
  if (strcmp (path, ".") == 0 || strcmp (path, "..") == 0)
    {
      // If it is, no encryption is applied
      result = strdup (path);
      if (!result)
        {
          logErr ("allocating memory");
          exit (EXIT_FAILURE);
        }
      logDebug ("encrypt path got a special case, returning %s\n", result);
      return result;
    }
  // Check if the path is /
  else if (strcmp (path, "/") == 0)
    {
      logDebug ("got root path\n");
      result = malloc (1 * sizeof (char));
      if (result == NULL)
        {
          logErr ("allocating memory");
          return NULL;
        }
      result[0] = '\0';
    }

  // Copy the original path
  char *path_copy = strdup (path);
  if (!path_copy)
    {
      logErr ("cannot allocate memory");
      exit (EXIT_FAILURE);
    }

  // Start encryption
  token = strtok_r (path_copy, "/", &saveptr);
  while (token != NULL)
    {
      // Check if the directory is "." or ".."
      if (strcmp (token, ".") == 0 || strcmp (token, "..") == 0)
        {
          // If it is, no encryption is applied
        }
      else
        {
          // Encrypt each part of the path
          const char *encrypted_part = encrypt_file_name_with_hex (token, key);

          // Concatenate to the result string
          if (result == NULL)
            {
              // Check if the first character of encrypted_part is '/'
              if (encrypted_part[0] != '/')
                {
                  result = malloc (strlen (encrypted_part) + 2);
                  if (!result)
                    {
                      logErr ("Cannot allocate memory");
                      free ((void *)path_copy);
                      exit (EXIT_FAILURE);
                    }
                  strcpy (result, "/");
                  strcat (result, encrypted_part);
                }
              else
                {
                  result = strdup (encrypted_part);
                }
            }
          else
            {
              size_t result_len = strlen (result);
              size_t encrypted_len = strlen (encrypted_part);

              result = realloc (result, result_len + 1 + encrypted_len + 1);
              if (!result)
                {
                  logErr ("Cannot allocate memory");
                  exit (EXIT_FAILURE);
                }

              // Check if the first character of encrypted_part is '/'
              if (encrypted_part[0] != '/')
                {
                  strcat (result, "/");
                }

              strcat (result, encrypted_part);
              logDebug ("Tempresult: %s\n", result);
            }
        }

      // Move to the next part of the path
      token = strtok_r (NULL, "/", &saveptr);
    }

  // Free the memory allocated for the path copy
  free (path_copy);

  return result;
}

/**
 * @brief Encrypts the given filename with its path using a specified key.
 * @param path The input path to be encrypted.
 * @param key The encryption key.
 * @return A dynamically allocated string containing the encrypted path with
 * the encrypted filename. It is the responsibility of the caller to free this
 * memory.
 */
const char *
encrypt_path_and_filename (const char *path, const char *key)
{
  char *result = NULL;
  char *token, *saveptr;

  // Check if the path is ".", ".."
  if (strcmp (path, ".") == 0 || strcmp (path, "..") == 0)
    {
      // If it is, no encryption is applied
      result = strdup (path);
      if (!result)
        {
          logErr ("Cannot allocate memory");
          exit (EXIT_FAILURE);
        }
      return result;
    }
  // Check if the path is /
  else if (strcmp (path, "/") == 0)
    {
      logDebug ("got root path\n");
      result = malloc (1 * sizeof (char));
      if (result == NULL)
        {
          logErr ("Cannot allocate memory");
          return NULL;
        }
      result[0] = '\0';
    }

  // Copy the original path
  char *path_copy = strdup (path);
  if (!path_copy)
    {
      logErr ("Cannot allocate memory");
      exit (EXIT_FAILURE);
    }

  // Start encryption
  token = strtok_r (path_copy, "/", &saveptr);
  while (token != NULL)
    {
      // Check if the directory is "." or ".."
      if (strcmp (token, ".") == 0 || strcmp (token, "..") == 0)
        {
          // If it is, no encryption is applied
        }
      else
        {
          // Encrypt each part of the path
          const char *encrypted_part = encrypt_file_name_with_hex (token, key);
          logDebug ("\tEncrypted %s --> %s\n", token, encrypted_part);

          // Concatenate to the result string
          if (result == NULL)
            {
              // Check if the first character of encrypted_part is '/'
              if (encrypted_part[0] != '/')
                {
                  result = malloc (strlen (encrypted_part) + 2);
                  if (!result)
                    {
                      logErr ("Cannot allocate memory");
                      exit (EXIT_FAILURE);
                    }
                  strcpy (result, "/");
                  strcat (result, encrypted_part);
                }
              else
                {
                  result = strdup (encrypted_part);
                }
            }
          else
            {
              size_t result_len = strlen (result);
              size_t encrypted_len = strlen (encrypted_part);

              result = realloc (result, result_len + 1 + encrypted_len + 1);
              if (!result)
                {
                  logErr ("Cannot allocate memory");
                  exit (EXIT_FAILURE);
                }

              // Check if the first character of encrypted_part is '/'
              if (encrypted_part[0] != '/')
                {
                  strcat (result, "/");
                }

              strcat (result, encrypted_part);
              logDebug ("Tempresult: %s\n", result);
            }
        }

      // Move to the next part of the path
      token = strtok_r (NULL, "/", &saveptr);
    }

  // Free the memory allocated for the path copy
  free (path_copy);

  return result;
}

/**
 * @brief Decrypts each part of the given encrypted path using a specified key.
 * @param encrypted_path The input encrypted path to be decrypted.
 * @param key The decryption key.
 * @return A dynamically allocated string containing the decrypted path.
 *         It is the responsibility of the caller to free this memory.
 */
const char *
decrypt_path (const char *encrypted_path, const char *key)
{
  logDebug ("decrypt path got %s\n", encrypted_path);
  char *result = NULL;
  char *token, *saveptr;

  // Check if the encrypted_path is ".", ".."
  if (strcmp (encrypted_path, ".") == 0 || strcmp (encrypted_path, "..") == 0)
    {
      // If it is, no decryption is applied
      result = strdup (encrypted_path);
      if (!result)
        {
          logErr ("Error allocating memory");
          exit (EXIT_FAILURE);
        }
      logDebug ("decrypt_path got a special case, returning %s\n", result);
      return result;
    }
  // Check if the encrypted_path is /
  else if (strcmp (encrypted_path, "/") == 0)
    {
      logDebug ("got root path\n");
      result = malloc (1 * sizeof (char));
      if (result == NULL)
        {
          logErr ("Cannot allocate memory");
          return NULL;
        }
      result[0] = '\0';
    }

  // Copy the original encrypted_path
  char *encrypted_path_copy = strdup (encrypted_path);
  if (!encrypted_path_copy)
    {
      logErr ("Error allocating memory");
      exit (EXIT_FAILURE);
    }

  // Start decryption
  token = strtok_r (encrypted_path_copy, "/", &saveptr);
  while (token != NULL)
    {
      // Check if the directory is "." or ".."
      if (strcmp (token, ".") == 0 || strcmp (token, "..") == 0)
        {
          // If it is, no decryption is applied
        }
      else
        {
          // Decrypt each part of the path
          const char *decrypted_part = decrypt_file_name_with_hex (token, key);
          logDebug ("Decrypted %s --> %s", token, decrypted_part);

          // Concatenate to the result string
          if (result == NULL)
            {
              // Check if the first character of decrypted_part is '/'
              if (decrypted_part[0] != '/')
                {
                  result = malloc (strlen (decrypted_part) + 2);
                  if (!result)
                    {
                      logErr ("Error allocating memory");
                      exit (EXIT_FAILURE);
                    }
                  strcpy (result, "/");
                  strcat (result, decrypted_part);
                }
              else
                {
                  result = strdup (decrypted_part);
                }
            }
          else
            {
              size_t result_len = strlen (result);
              size_t decrypted_len = strlen (decrypted_part);

              result = realloc (result, result_len + 1 + decrypted_len + 1);
              if (!result)
                {
                  logErr ("Error allocating memory");
                  exit (EXIT_FAILURE);
                }

              // Check if the first character of decrypted_part is '/'
              if (decrypted_part[0] != '/')
                {
                  strcat (result, "/");
                }

              strcat (result, decrypted_part);
              logDebug ("Tempresult: %s", result);
            }
        }

      // Move to the next part of the encrypted_path
      token = strtok_r (NULL, "/", &saveptr);
    }

  // Free the memory allocated for the encrypted_path copy
  logDebug ("encrypted_path_copy %s", encrypted_path_copy);
  free (encrypted_path_copy);

  logDebug ("decrypt_path will return %s", result);
  return result;
}

/**
 * @brief Decrypts the given encrypted filename with its path using a specified
 * key.
 * @param encrypted_path The input encrypted path to be decrypted.
 * @param key The decryption key.
 * @return A dynamically allocated string containing the decrypted path with
 * the decrypted filename. It is the responsibility of the caller to free this
 * memory.
 * @note This function has currently no use
 */
const char *
decrypt_path_and_filename (const char *encrypted_path, const char *key)
{
  char *result = NULL;
  char *token, *saveptr;

  // Check if the encrypted_path is ".", ".."
  if (strcmp (encrypted_path, ".") == 0 || strcmp (encrypted_path, "..") == 0)
    {
      // If it is, no decryption is applied
      result = strdup (encrypted_path);
      if (!result)
        {
          logErr ("Error allocating memory");
          exit (EXIT_FAILURE);
        }
      logDebug ("decrypt_filename_with_path got a special case, returning %s",
                result);
      return result;
    }
  // Check if the encrypted_path is /
  else if (strcmp (encrypted_path, "/") == 0)
    {
      logDebug ("got root path");
      result = malloc (1 * sizeof (char));
      if (result == NULL)
        {
          logErr ("Cannot allocate memory");
          return NULL;
        }
      result[0] = '\0';
    }

  // Copy the original encrypted_path
  char *encrypted_path_copy = strdup (encrypted_path);
  if (!encrypted_path_copy)
    {
      logErr ("Cannot allocate memory");
      exit (EXIT_FAILURE);
    }

  // Start decryption
  token = strtok_r (encrypted_path_copy, "/", &saveptr);
  while (token != NULL)
    {
      // Check if the directory is "." or ".."
      if (strcmp (token, ".") == 0 || strcmp (token, "..") == 0)
        {
          // If it is, no decryption is applied
        }
      else
        {
          // Decrypt each part of the path
          const char *decrypted_part = decrypt_file_name_with_hex (token, key);
          logDebug ("Decrypted %s --> %s", token, decrypted_part);

          // Concatenate to the result string
          if (result == NULL)
            {
              // Check if the first character of decrypted_part is '/'
              if (decrypted_part[0] != '/')
                {
                  result = malloc (strlen (decrypted_part) + 2);
                  if (!result)
                    {
                      logErr ("Cannot allocate memory");
                      exit (EXIT_FAILURE);
                    }
                  strcpy (result, "/");
                  strcat (result, decrypted_part);
                }
              else
                {
                  result = strdup (decrypted_part);
                }
            }
          else
            {
              size_t result_len = strlen (result);
              size_t decrypted_len = strlen (decrypted_part);

              result = realloc (result, result_len + 1 + decrypted_len + 1);
              if (!result)
                {
                  logErr ("Cannot allocate memory");
                  exit (EXIT_FAILURE);
                }

              // Check if the first character of decrypted_part is '/'
              if (decrypted_part[0] != '/')
                {
                  strcat (result, "/");
                }

              strcat (result, decrypted_part);
              logDebug ("Tempresult: %s", result);
            }
        }

      // Move to the next part of the encrypted_path
      token = strtok_r (NULL, "/", &saveptr);
    }

  // Free the memory allocated for the encrypted_path copy
  logDebug ("encrypted_path_copy %s\n", encrypted_path_copy);
  free (encrypted_path_copy);

  logDebug ("decrypt_filename_with_path will return %s\n", result);
  return result;
}

/**
 * @brief
 * This function generates a random Initialization Vector (IV) for AES
 * encryption.
 *
 * @return
 * Returns a pointer to the generated IV.
 * In case of an error, it prints an error message and returns NULL.
 *
 * @note
 * This function uses OpenSSL's RAND_bytes function to generate a random IV.
 * The size of the IV is defined by the IV_SIZE macro.
 * The generated IV is dynamically allocated and it is the responsibility of
 * the caller to free it.
 */
extern unsigned char *
generate_iv (void)
{
  logDebug ("Generating IV...");
  unsigned char *iv = malloc (IV_SIZE);
  if (iv == NULL)
    {
      logErr ("Cannot allocate memory for IV");
      return NULL;
    }
  // Generate a random IV
  if (RAND_bytes (iv, IV_SIZE) != 1)
    {
      logErr ("Cannot generate IV");
      free (iv);
      return NULL;
    }
  return iv;
}

unsigned char *
encrypt_buffer (const char *buf, size_t size, unsigned char *key)
{
  // Create and initialize the context
  EVP_CIPHER_CTX *ctx;
  if (!(ctx = EVP_CIPHER_CTX_new ()))
    {
      logErr ("Cannot create new EVP_CIPHER_CTX");
      return NULL;
    }

  // Initialize the encryption operation
  if (1 != EVP_EncryptInit_ex (ctx, EVP_aes_256_ctr (), NULL, key, NULL))
    {
      logErr ("Cannot initialize encryption");
      EVP_CIPHER_CTX_free (ctx);
      return NULL;
    }

  // Provide the message to be encrypted, and obtain the encrypted output
  unsigned char *encrypted_buf = malloc (size + EVP_MAX_BLOCK_LENGTH);
  int len;
  if (1
      != EVP_EncryptUpdate (ctx, encrypted_buf, &len,
                            (const unsigned char *)buf, (int)size))
    {
      logErr ("Cannot encrypt buffer");
      EVP_CIPHER_CTX_free (ctx);
      free (encrypted_buf);
      return NULL;
    }

  // Finalize the encryption
  int ciphertext_len = len;
  if (1 != EVP_EncryptFinal_ex (ctx, encrypted_buf + len, &len))
    {
      logErr ("Cannot finalize encryption");
      EVP_CIPHER_CTX_free (ctx);
      free (encrypted_buf);
      return NULL;
    }
  ciphertext_len += len;

  // Clean up
  EVP_CIPHER_CTX_free (ctx);

  return encrypted_buf;
}
