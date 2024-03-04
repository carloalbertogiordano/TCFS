#include "ctr_encryption_handler.h"

/**
 * @internal @_file
 * @file ctr_encryption_handler.c
 * @brief File containing the AES CTR mode file encryption and decryption
 * functions.
 *
 * This file contains the following functions:
 * - encrypt_file_aes_ctr: Encrypts a file using AES CTR mode.
 * - decrypt_file_aes_ctr: Decrypts a file using AES CTR mode.
 *
 * Both functions handle errors and clean up resources if an error occurs
 * during the encryption or decryption process.
 */

/**
 * @internal @_func
 * @brief Encrypts a file using AES CTR mode.
 * @param fp File pointer to the file to be encrypted.
 * @param plaintext Pointer to the plaintext to be encrypted.
 * @param plaintext_len Length of the plaintext.
 * @param key Pointer to the encryption key.
 * @param iv Pointer to the initialization vector.
 * @return The length of the ciphertext on success, false on failure.
 *
 * This function encrypts a file using AES CTR mode. It writes the ciphertext
 * and its length to the file. In case of any error during the encryption
 * process, it cleans up any allocated resources and returns false.
 */
extern int
encrypt_file_aes_ctr (FILE *fp, unsigned char *plaintext, int plaintext_len,
                      unsigned char *key, unsigned char *iv)
{
  EVP_CIPHER_CTX *ctx = NULL;
  unsigned char *ciphertext = NULL;
  size_t len;
  size_t ciphertext_len;

  if (setjmp (jump_buffer))
    {
      /* An error occurred */
      if (ctx)
        EVP_CIPHER_CTX_free (ctx);
      if (ciphertext)
        free (ciphertext);
      return false;
    }

  /* Create a new context */
  ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    handleErrors ();

  /* Initialize the encryption operation. */
  if (1 != EVP_EncryptInit_ex (ctx, EVP_aes_256_ctr (), NULL, key, iv))
    handleErrors ();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  ciphertext = malloc (plaintext_len + EVP_MAX_BLOCK_LENGTH);
  if (!ciphertext)
    handleErrors ();

  if (1 != EVP_EncryptUpdate (ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors ();
  ciphertext_len = len;

  /* Write the ciphertext length to the file */
  if (fwrite (&ciphertext_len, sizeof (int), 1, fp) != 1)
    handleErrors ();

  /* Write the ciphertext to the file */
  if ((int)fwrite (ciphertext, sizeof (unsigned char), ciphertext_len, fp)
      != ciphertext_len)
    handleErrors ();

  /* Clean up */
  EVP_CIPHER_CTX_free (ctx);
  free (ciphertext);

  return ciphertext_len;
}

/**
 * @internal @_func
 * @brief Decrypts a file using AES CTR mode.
 * @param fp File pointer to the file to be decrypted.
 * @param plaintext Pointer to the buffer where the decrypted plaintext will be
 * stored.
 * @param key Pointer to the decryption key.
 * @param iv Pointer to the initialization vector.
 * @return The length of the plaintext on success, -1 on failure.
 *
 * This function decrypts a file encrypted using AES CTR mode. It reads the
 * ciphertext and its length from the file, decrypts it, and stores the
 * plaintext in the provided buffer. In case of any error during the decryption
 * process, it cleans up any allocated resources and returns -1.
 */
extern int
decrypt_file_aes_ctr (FILE *fp, unsigned char **plaintext, unsigned char *key,
                      unsigned char *iv, size_t bytes_to_read, off_t offset)
{
  size_t len;
  size_t ciphertext_len;
  size_t aligned_offset = 0;
  size_t bytes_read = 0L;
  size_t bytes_read_prev = 0L;
  off_t seek_value = 0L;

  unsigned char *ciphertext = NULL;
  volatile size_t plaintext_len = 0;
  EVP_CIPHER_CTX *ctx = NULL;

  if (setjmp (jump_buffer))
    {
      if (ciphertext)
        free (ciphertext);
      if (ctx)
        EVP_CIPHER_CTX_free (ctx);
      return 0;
    }

  // Get file size
  fseek (fp, 0, SEEK_END);
  long fsize = ftell (fp);
  fseek (fp, 0, SEEK_SET); // same as rewind(f);

  // Align to offset
  if (offset > fsize)
    {
      aligned_offset = offset;
    }
  while (offset > aligned_offset && offset < fsize)
    {
      fread (&seek_value, sizeof (int), 1, fp);
      bytes_read += (unsigned long)sizeof (int);
      logDebug ("Next block size: %lu", seek_value);
      fseek (fp, seek_value, SEEK_CUR);
      bytes_read += seek_value;
      logDebug ("Bytes_read:%lu", bytes_read);
      aligned_offset += seek_value;
      logDebug ("New alignedOff: %lu", aligned_offset);
      if (aligned_offset > offset)
        {
          logDebug ("Offset overshoot");
          bytes_read = bytes_read_prev;
          break;
        }
      else if (aligned_offset == offset)
        {
          logDebug ("Offset Found");
          break;
        }
      else
        {
          logDebug ("Offset not found yet, off:%lu align:%lu bytes_read:%lu "
                    "lase bytes_read",
                    offset, aligned_offset, bytes_read, bytes_read_prev);
        }
      bytes_read_prev = bytes_read;
    }

  logDebug ("Off:%lu is at byte:%lu", offset, bytes_read);

  fseek (fp, bytes_read, SEEK_SET);

  // Read the ciphertext from the file block by block
  while (ftell (fp) < fsize && plaintext_len < bytes_to_read)
    {
      ctx = NULL;

      // Read the length of the ciphertext block from the file
      if (fread (&ciphertext_len, sizeof (int), 1, fp) != 1)
        handleErrors ();
      logDebug ("Cyphertxt len %lu, allocating %lu", ciphertext_len,
                ciphertext_len);

      // Allocate memory for the ciphertext
      ciphertext = (unsigned char *)malloc (ciphertext_len);
      if (!ciphertext)
        handleErrors ();

      // Read the ciphertext block from the file
      if ((int)fread (ciphertext, sizeof (unsigned char), ciphertext_len, fp)
          != ciphertext_len)
        handleErrors ();
      logDebug ("Cyphertext read");

      // Create a new decryption context
      ctx = EVP_CIPHER_CTX_new ();
      if (!ctx)
        handleErrors ();

      // Initialize the context with the keys and the IV
      if (!EVP_DecryptInit_ex (ctx, EVP_aes_256_ctr (), NULL, key, iv))
        handleErrors ();

      // Reallocate memory for the plaintext if necessary
      *plaintext = (unsigned char *)realloc (*plaintext,
                                             plaintext_len + ciphertext_len);
      if (!*plaintext)
        handleErrors ();
      logDebug ("Mem reallocated succ");

      // Decrypt the ciphertext
      if (!EVP_DecryptUpdate (ctx, *plaintext + plaintext_len, &len,
                              ciphertext, ciphertext_len))
        handleErrors ();
      logDebug ("Decypher complete");

      // Update the plaintext length
      plaintext_len += len;

      logDebug ("Cyphertxt len %lu", plaintext_len);

      // Free the context
      EVP_CIPHER_CTX_free (ctx);

      // Free the ciphertext memory
      free (ciphertext);
    }

  return plaintext_len;
}
