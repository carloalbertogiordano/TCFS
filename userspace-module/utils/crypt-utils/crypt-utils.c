/***

 *
 **/
#include "crypt-utils.h"

/**
 * @internal
 * @def BLOCKSIZE
 * @brief This defines the max size of a block that can be cyphered. \_def
 * */
#define BLOCKSIZE 1024
/**
 * @internal
 * @def IV_SIZE
 * @brief The fixed size of the initialization vector \link
 * https://en.wikipedia.org/wiki/Initialization_vector IV \endlink. \_def
 * */
#define IV_SIZE 32
/**
 * @internal
 * @def KEY_SIZE
 * @brief The fixed size of the key. \_def
 * */
#define KEY_SIZE 32

/**
 * @brief
 * High level function interface for performing AES encryption on FILE pointers
 * Uses OpenSSL libcrypto EVP API \n
 *
 * @author
 * By Andy Sayler (www.andysayler.com) \n
 * Created  04/17/12 \n
 * @author
 * Modified 18/10/23 by [Carlo Alberto Giordano] \n
 *
 *@brief
 * Derived from OpenSSL.org EVP_Encrypt_* Manpage Examples \n
 * http://www.openssl.org/docs/crypto/EVP_EncryptInit.html#EXAMPLES \n
 *
 * With additional information from Saju Pillai's OpenSSL AES Example \n
 * http://saju.net.in/blog/?p=36 \n
 * http://saju.net.in/code/misc/openssl_aes.c.txt \n
 * @param in  The input file
 * @param out The output file
 * @param action    Defines if the action to do on the input file should be
 *of encryption or decryption. \see ENCRYPT \see DECRYPT
 * @param key_str The key that must be AES 256
 * @return \ret
 * @note This function cyphers using AES 256 CBC
 * */
extern int
do_crypt (FILE *in, FILE *out, int action, unsigned char *key_str)
{
  /* Local Vars */

  /* Buffers */
  unsigned char inbuf[BLOCKSIZE];
  int inlen;
  /* Allow enough space in output buffer for additional cipher block */
  unsigned char outbuf[BLOCKSIZE + EVP_MAX_BLOCK_LENGTH];
  int outlen;
  int writelen;

  /* OpenSSL libcrypto vars */
  EVP_CIPHER_CTX *ctx;
  ctx = EVP_CIPHER_CTX_new ();

  unsigned char key[KEY_SIZE];
  unsigned char iv[IV_SIZE];
  int nrounds = 5;

  /* tmp vars */
  int i;
  /* Setup Encryption Key and Cipher Engine if in cipher mode */
  if (action >= 0)
    {
      if (!key_str)
        {
          /* Error */
          fprintf (stderr, "Key_str must not be NULL\n");
          return 0;
        }
      /* Build Key from String */
      i = EVP_BytesToKey (EVP_aes_256_cbc (), EVP_sha1 (), NULL, key_str,
                          (int)strlen ((const char *)key_str), nrounds, key,
                          iv);
      if (i != 32)
        {
          /* Error */
          fprintf (stderr, "Key size is %d bits - should be 256 bits\n",
                   i * 8);
          return 0;
        }
      /* Init Engine */
      EVP_CIPHER_CTX_init (ctx);
      EVP_CipherInit_ex (ctx, EVP_aes_256_cbc (), NULL, key, iv, action);
    }

  /* Loop through Input File*/
  for (;;)
    {
      /* Read Block */
      inlen = fread (inbuf, sizeof (*inbuf), BLOCKSIZE, in);
      if (inlen <= 0)
        {
          /* EOF -> Break Loop */
          break;
        }

      /* If in cipher mode, perform cipher transform on block */
      if (action >= 0)
        {
          if (!EVP_CipherUpdate (ctx, outbuf, &outlen, inbuf, inlen))
            {
              /* Error */
              EVP_CIPHER_CTX_cleanup (ctx);
              return 0;
            }
        }
      /* If in pass-through mode. copy block as is */
      else
        {
          memcpy (outbuf, inbuf, inlen);
          outlen = inlen;
        }

      /* Write Block */
      writelen = fwrite (outbuf, sizeof (*outbuf), outlen, out);
      if (writelen != outlen)
        {
          /* Error */
          perror ("fwrite error");
          EVP_CIPHER_CTX_cleanup (ctx);
          return 0;
        }
    }

  /* If in cipher mode, handle necessary padding */
  if (action >= 0)
    {
      /* Handle remaining cipher block + padding */
      if (!EVP_CipherFinal_ex (ctx, outbuf, &outlen))
        {
          /* Error */
          EVP_CIPHER_CTX_cleanup (ctx);
          return 0;
        }
      /* Write remainign cipher block + padding*/
      fwrite (outbuf, sizeof (*inbuf), outlen, out);
      EVP_CIPHER_CTX_cleanup (ctx);
    }

  /* Success */
  return 1;
}

/**
 * @internal \_func
 * @brief Verify if there is enough entropy in the system to generate a key
 * @param void
 * @return A value greater than 0 corresponding to the entropy level, if an
 * error occurs -1 is returned
 * @note This function evaluates the entropy by checking the
 * /proc/sys/kernel/random/entropy_avail file. \see man page 4 for random
 * */
int
check_entropy (void)
{
  FILE *entropy_file = fopen ("/proc/sys/kernel/random/entropy_avail", "r");
  if (entropy_file == NULL)
    {
      perror ("Err: Cannot open entropy file");
      return -1;
    }

  int entropy_value;
  if (fscanf (entropy_file, "%d", &entropy_value) != 1)
    {
      perror ("Err: Cannot estimate entropy");
      fclose (entropy_file);
      return -1;
    }

  fclose (entropy_file);
  return entropy_value;
}

/**
 * @internal
 * @brief Force new entropy in /dev/urandom, \_func
 * @param void
 * @return void
 * @note Very dangerous, if this fails an error will be printed and the program
 * will exit with EXIT_FAILURE
 * */
void
add_entropy (void)
{
  FILE *urandom = fopen ("/dev/urandom", "rb");
  if (urandom == NULL)
    {
      perror ("Err: Cannot open /dev/urandom");
      exit (EXIT_FAILURE);
    }

  unsigned char random_data[32];
  size_t bytes_read = fread (random_data, 1, sizeof (random_data), urandom);
  fclose (urandom);

  if (bytes_read != sizeof (random_data))
    {
      fprintf (stderr, "Err: Cannot read data\n");
      exit (EXIT_FAILURE);
    }

  // Usa i dati casuali per aggiungere entropia
  RAND_add (random_data, sizeof (random_data),
            0.5); // 0.5 è un peso arbitrario

  fprintf (stdout, "Entropy added successfully!\n");
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
  fprintf (stdout, "Generating a new key...\n");

  // Why? Because if we try to create a large number of files there might not
  // be enough random bytes in the system to generate a key
  for (int i = 0; i < 10; i++)
    {
      int entropy = check_entropy ();
      if (entropy < 128)
        {
          fprintf (stderr, "WARN: not enough entropy, creating some...\n");
          add_entropy ();
        }

      if (RAND_bytes (destination, 32) != 1)
        {
          fprintf (stderr, "Err: Cannot generate key\n");
          destination = NULL;
        }

      if (strlen ((const char *)destination) == 32)
        break;
    }

  if (is_valid_key (destination) == 0)
    {
      fprintf (stderr, "Err: Generated key is inval1d\n");
      print_aes_key (destination);
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
 * @note    After the use remember to free the result
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

  int len;
  EVP_EncryptUpdate (ctx, ciphertext, &len, plaintext, plaintext_len);
  EVP_EncryptFinal_ex (ctx, ciphertext + len, &len);
  EVP_CIPHER_CTX_free (ctx);

  unsigned char *encoded_string = malloc (len * 2 + 1);
  if (!encoded_string)
    {
      return NULL;
    }

  for (int i = 0; i < len; i++)
    {
      sprintf ((char *)&encoded_string[i * 2], "%02x", ciphertext[i]);
    }
  encoded_string[len * 2] = '\0';

  *encrypted_key_len = len * 2;
  return encoded_string;
}

/**
 * @brief Decrypt the *ciphertext string using a AES 256 key
 * @param ciphertext  This is the string to decrypt
 * @param key The AES 256 KEY
 * @return unsigned char *  The plaintext string will be allocated and then
 * returned
 * @note    After the use remember to free the result
 * */
unsigned char *
decrypt_string (unsigned char *ciphertext, const char *key)
{
  EVP_CIPHER_CTX *ctx;
  const EVP_CIPHER *cipher
      = EVP_aes_256_cbc (); // Choose the correct algorithm
  unsigned char iv[AES_BLOCK_SIZE];
  memset (iv, 0, AES_BLOCK_SIZE);

  ctx = EVP_CIPHER_CTX_new ();
  EVP_DecryptInit_ex (ctx, cipher, NULL, (const unsigned char *)key, iv);

  size_t decoded_len = strlen ((const char *)ciphertext);

  unsigned char plaintext[decoded_len];
  memset (plaintext, 0, sizeof (plaintext));

  int len;
  EVP_DecryptUpdate (ctx, plaintext, &len, ciphertext, (int)decoded_len);
  EVP_DecryptFinal_ex (ctx, plaintext + len, &len);
  EVP_CIPHER_CTX_free (ctx);

  unsigned char *decrypted_string = (unsigned char *)malloc (decoded_len + 1);
  memcpy (decrypted_string, plaintext, decoded_len);
  decrypted_string[decoded_len] = '\0';

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
  return key_length != 32 ? 0 : 1;
}

/*
int rebuild_key(char *key, char *cert, char *dest){
    return -1;
}*/

/**
 * @brief Verifica se la stringa fornita è una stringa esadecimale valida
 * @param str La stringa da verificare
 * @return true se la stringa è esadecimale, false altrimenti
 */
int
is_hex_string (const char *str)
{
  while (*str)
    {
      if (!isxdigit (*str))
        {
          return 1;
        }
      str++;
    }
  return 0;
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
  return (const char *)hex_to_string ((const char *)decrypt_string (
      (unsigned char *)hex_to_string (enc_file), key));
}

/**
 * @brief Encrypts each part of the given path using a specified key.
 *
 * This function takes a path, divides it into segments separated by '/',
 * and encrypts each segment using the provided encryption key. Directories
 * ".", ".." and "/" are excluded from encryption.
 *
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
          perror ("Error allocating memory");
          exit (EXIT_FAILURE);
        }
      printf ("\tencrypt path got a special case, returning %s\n", result);
      return result;
    }
  // Check if the path is /
  else if (strcmp (path, "/") == 0)
    {
      printf ("\tgot root path\n");
      return "";
    }

  // Copy the original path
  char *path_copy = strdup (path);
  if (!path_copy)
    {
      perror ("Error allocating memory");
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
          printf ("\tEncrypted %s --> %s\n", token, encrypted_part);

          // Concatenate to the result string
          if (result == NULL)
            {
              // Check if the first character of encrypted_part is '/'
              if (encrypted_part[0] != '/')
                {
                  result = malloc (strlen (encrypted_part) + 2);
                  if (!result)
                    {
                      perror ("Error allocating memory");
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
                  perror ("Error allocating memory");
                  exit (EXIT_FAILURE);
                }

              // Check if the first character of encrypted_part is '/'
              if (encrypted_part[0] != '/')
                {
                  strcat (result, "/");
                }

              strcat (result, encrypted_part);
              printf ("\t\tTempresult: %s\n", result);
            }
        }

      // Move to the next part of the path
      token = strtok_r (NULL, "/", &saveptr);
    }

  // Free the memory allocated for the path copy
  printf ("\t\tpathcopy %s\n", path_copy);
  free (path_copy);

  printf ("\tencrypt_path will return %s\n", result);
  return result;
}

/**
 * @brief Encrypts the given filename with its path using a specified key.
 *
 * This function takes a filename with its path, divides it into segments
 * separated by '/', and encrypts each segment using the provided encryption
 * key. Directories ".", ".." and "/" are excluded from encryption.
 *
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
          perror ("Error allocating memory");
          exit (EXIT_FAILURE);
        }
      printf (
          "\tencrypt_filename_with_path got a special case, returning %s\n",
          result);
      return result;
    }
  // Check if the path is /
  else if (strcmp (path, "/") == 0)
    {
      printf ("\tgot root path\n");
      return "";
    }

  // Copy the original path
  char *path_copy = strdup (path);
  if (!path_copy)
    {
      perror ("Error allocating memory");
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
          printf ("\tEncrypted %s --> %s\n", token, encrypted_part);

          // Concatenate to the result string
          if (result == NULL)
            {
              // Check if the first character of encrypted_part is '/'
              if (encrypted_part[0] != '/')
                {
                  result = malloc (strlen (encrypted_part) + 2);
                  if (!result)
                    {
                      perror ("Error allocating memory");
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
                  perror ("Error allocating memory");
                  exit (EXIT_FAILURE);
                }

              // Check if the first character of encrypted_part is '/'
              if (encrypted_part[0] != '/')
                {
                  strcat (result, "/");
                }

              strcat (result, encrypted_part);
              printf ("\t\tTempresult: %s\n", result);
            }
        }

      // Move to the next part of the path
      token = strtok_r (NULL, "/", &saveptr);
    }

  // Free the memory allocated for the path copy
  printf ("\t\tpathcopy %s\n", path_copy);
  free (path_copy);

  printf ("\tencrypt_filename_with_path will return %s\n", result);
  return result;
}

/**
 * @brief Decrypts each part of the given encrypted path using a specified key.
 *
 * This function takes an encrypted path, divides it into segments separated by
 * '/', and decrypts each segment using the provided decryption key.
 * Directories
 * ".", ".." and "/" are excluded from decryption.
 *
 * @param encrypted_path The input encrypted path to be decrypted.
 * @param key The decryption key.
 * @return A dynamically allocated string containing the decrypted path.
 *         It is the responsibility of the caller to free this memory.
 */
const char *
decrypt_path (const char *encrypted_path, const char *key)
{
  printf ("decrypt path got %s\n", encrypted_path);
  char *result = NULL;
  char *token, *saveptr;

  // Check if the encrypted_path is ".", ".."
  if (strcmp (encrypted_path, ".") == 0 || strcmp (encrypted_path, "..") == 0)
    {
      // If it is, no decryption is applied
      result = strdup (encrypted_path);
      if (!result)
        {
          perror ("Error allocating memory");
          exit (EXIT_FAILURE);
        }
      printf ("\tdecrypt_path got a special case, returning %s\n", result);
      return result;
    }
  // Check if the encrypted_path is /
  else if (strcmp (encrypted_path, "/") == 0)
    {
      printf ("\tgot root path\n");
      return "";
    }

  // Copy the original encrypted_path
  char *encrypted_path_copy = strdup (encrypted_path);
  if (!encrypted_path_copy)
    {
      perror ("Error allocating memory");
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
          printf ("\tDecrypted %s --> %s\n", token, decrypted_part);

          // Concatenate to the result string
          if (result == NULL)
            {
              // Check if the first character of decrypted_part is '/'
              if (decrypted_part[0] != '/')
                {
                  result = malloc (strlen (decrypted_part) + 2);
                  if (!result)
                    {
                      perror ("Error allocating memory");
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
                  perror ("Error allocating memory");
                  exit (EXIT_FAILURE);
                }

              // Check if the first character of decrypted_part is '/'
              if (decrypted_part[0] != '/')
                {
                  strcat (result, "/");
                }

              strcat (result, decrypted_part);
              printf ("\t\tTempresult: %s\n", result);
            }
        }

      // Move to the next part of the encrypted_path
      token = strtok_r (NULL, "/", &saveptr);
    }

  // Free the memory allocated for the encrypted_path copy
  printf ("\t\tencrypted_path_copy %s\n", encrypted_path_copy);
  free (encrypted_path_copy);

  printf ("\tdecrypt_path will return %s\n", result);
  return result;
}

/**
 * @brief Decrypts the given encrypted filename with its path using a specified
 * key.
 *
 * This function takes an encrypted filename with its path, divides it into
 * segments separated by '/', and decrypts each segment using the provided
 * decryption key. Directories ".", ".." and "/" are excluded from decryption.
 *
 * @param encrypted_path The input encrypted path to be decrypted.
 * @param key The decryption key.
 * @return A dynamically allocated string containing the decrypted path with
 * the decrypted filename. It is the responsibility of the caller to free this
 * memory.
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
          perror ("Error allocating memory");
          exit (EXIT_FAILURE);
        }
      printf (
          "\tdecrypt_filename_with_path got a special case, returning %s\n",
          result);
      return result;
    }
  // Check if the encrypted_path is /
  else if (strcmp (encrypted_path, "/") == 0)
    {
      printf ("\tgot root path\n");
      return "";
    }

  // Copy the original encrypted_path
  char *encrypted_path_copy = strdup (encrypted_path);
  if (!encrypted_path_copy)
    {
      perror ("Error allocating memory");
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
          printf ("\tDecrypted %s --> %s\n", token, decrypted_part);

          // Concatenate to the result string
          if (result == NULL)
            {
              // Check if the first character of decrypted_part is '/'
              if (decrypted_part[0] != '/')
                {
                  result = malloc (strlen (decrypted_part) + 2);
                  if (!result)
                    {
                      perror ("Error allocating memory");
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
                  perror ("Error allocating memory");
                  exit (EXIT_FAILURE);
                }

              // Check if the first character of decrypted_part is '/'
              if (decrypted_part[0] != '/')
                {
                  strcat (result, "/");
                }

              strcat (result, decrypted_part);
              printf ("\t\tTempresult: %s\n", result);
            }
        }

      // Move to the next part of the encrypted_path
      token = strtok_r (NULL, "/", &saveptr);
    }

  // Free the memory allocated for the encrypted_path copy
  printf ("\t\tencrypted_path_copy %s\n", encrypted_path_copy);
  free (encrypted_path_copy);

  printf ("\tdecrypt_filename_with_path will return %s\n", result);
  return result;
}
