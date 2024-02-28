#include "gcm_encryption_handler.h"

/**
 * @file gcm_encryption_handler.c
 * @brief File containing the AES GCM mode file encryption and decryption functions.
 *
 * This file contains the following functions:
 * - encrypt_file_gcm: Encrypts a file using AES GCM mode.
 * - decrypt_file_gcm: Decrypts a file using AES GCM mode.
 *
 * Both functions handle errors and clean up resources if an error occurs during the encryption or decryption process.
 */

/**
 * @internal @_def
 * @def TAG_LEN
 * @brief The length of the authentication tag.
 */
#define TAG_LEN 16

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
 * @param offset The offset
 *
 * @return
 * Returns the length of the encrypted ciphertext.
 * In case of an error, it prints an error message and returns false.
 *
 * @note
 * This function encrypts using AES 256 GCM.
 * The function encrypts the plaintext and writes the ciphertext and the
 * authentication tag to the file. The function uses OpenSSL's EVP API for
 * encryption. For each block the function writes: block_size|block|TAG. The
 * decrypt_file_gcm depends on this behaviour.
 */
extern int
encrypt_file_gcm (FILE *fp, unsigned char *plaintext, size_t plaintext_len,
                  unsigned char *key, unsigned char *iv, off_t offset)
{
  EVP_CIPHER_CTX *ctx = NULL;
  int len;
  int ciphertext_len;
  unsigned char *ciphertext = NULL;
  unsigned char tag[TAG_LEN];

  if (setjmp (jump_buffer))
    {
      logErr (
          "An error occurred in encrypt_file_gcm! Freeing resources... error");
      EVP_CIPHER_CTX_free (ctx);
      if (ciphertext)
        free (ciphertext);
      return false;
    }

  // Align to offset
  off_t aligned_offset = (offset / TAG_LEN) * TAG_LEN;
  fseek (fp, aligned_offset, SEEK_SET);

  logDebug ("write offset:%ul aligned %ul", offset, aligned_offset);

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
 * * @param offset The offset
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
extern int
decrypt_file_gcm (FILE *fp, unsigned char *key, unsigned char *iv,
                  unsigned char **plaintext, size_t bytes_to_read, off_t offset)
{
  EVP_CIPHER_CTX *ctx = NULL;
  int len;
  volatile int plaintext_len = 0;
  unsigned char *ciphertext = NULL;
  unsigned char tag[TAG_LEN];
  *plaintext = NULL;

  if (setjmp (jump_buffer))
    {
      logErr (
          "An error occurred in decrypt_file_gcm! Freeing resources... error");
      if (ctx)
        EVP_CIPHER_CTX_free (ctx);
      if (ciphertext)
        free (ciphertext);
      return -1;
    }

  // Get file size
  fseek (fp, 0, SEEK_END);
  long fsize = ftell (fp);
  fseek (fp, 0, SEEK_SET); // same as rewind(f);

  // Align to offset
  off_t aligned_offset = (offset / TAG_LEN) * TAG_LEN;
  fseek (fp, aligned_offset, SEEK_SET);

  logDebug ("read offset:%ul aligned %ul", offset, aligned_offset);

  while (ftell (fp) < fsize && plaintext_len < bytes_to_read)
    {
      int ciphertext_len;
      fread (&ciphertext_len, sizeof (int), 1, fp);
      if (ciphertext_len < 0){
          logErr ("ciphertext_len is less than 0");
          handleErrors();
        }

      logDebug ("Allocating ciphertext of size %d", ciphertext_len);
      ciphertext = malloc (ciphertext_len);
      if (!ciphertext)
        {
          logErr ("ciphertext MEM err");
          handleErrors ();
        }

      fread (ciphertext, sizeof (unsigned char), ciphertext_len, fp);

      fread (tag, sizeof (unsigned char), TAG_LEN,
             fp); // Read the tag from the file

      if (!(ctx = EVP_CIPHER_CTX_new ()))
        {
          logErr ("CTX ERR MEM");
          handleErrors ();
        }

      if (1 != EVP_DecryptInit_ex (ctx, EVP_aes_256_gcm (), NULL, key, iv))
        {
          logErr ("EVP_DecryptInit_ex err");
          handleErrors ();
        }

      if (!EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag))
        {
          logErr ("EVP_CIPHER_CTX_ctrl err");
          handleErrors ();
        }

      *plaintext = realloc (*plaintext, plaintext_len + ciphertext_len);
      if (!*plaintext)
        {
          logErr ("plaintext err");
          handleErrors ();
        }

      if (1
          != EVP_DecryptUpdate (ctx, *plaintext + plaintext_len, &len,
                                ciphertext, ciphertext_len))
        {
          logErr ("EVP_DecryptUpdate");
          handleErrors ();
        }
      plaintext_len += len;

      EVP_CIPHER_CTX_free (ctx);

      free (ciphertext);
    }

  return plaintext_len;
}
