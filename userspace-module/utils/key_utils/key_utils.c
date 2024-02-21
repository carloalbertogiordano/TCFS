#include "../debug_utils/debug_helper.h"
#include <keyutils.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

/**
 * @brief Retrieves a key from the kernel keyring.
 *
 * This function retrieves a key from the kernel keyring given its ID as a
 * string. The key is read into a dynamically allocated buffer.
 *
 * @param key_id_str The ID of the key to retrieve, as a string.
 * @return A pointer to a buffer containing the key, or NULL if an error
 * occurred.
 */
unsigned char *
get_key (const char *key_id_str)
{
  key_serial_t key_id;
  long ret;

  sscanf (key_id_str, "%d", &key_id);

  // Get the size of the key
  ret = keyctl_read (key_id, NULL, 0);
  if (ret == -1)
    {
      logErr ("Failed to get the size of the key from the kernel keyring.");
      return NULL;
    }

  // Allocate enough memory for the key
  unsigned char *buffer = malloc (ret);
  if (buffer == NULL)
    {
      logErr ("Failed to allocate memory for the key buffer.");
      return NULL;
    }

  // Read the key into the buffer
  ret = keyctl_read (key_id, buffer, ret);
  if (ret == -1)
    {
      logErr ("Failed to read the key from the kernel keyring.");
      free (buffer);
      return NULL;
    }

  prctl (PR_SET_DUMPABLE, 0);

  return buffer;
}

/**
 * @brief Frees a key retrieved with get_key.
 *
 * This function overwrites the memory used to store the key with zeros, then
 * frees the memory. The memory containing the key is unlocked, and the process
 * is allowed to generate a core dump again.
 *
 * @param key A pointer to the key to free.
 */
void
free_key (const char *key)
{
  // Overwrite the memory used to store the key
  memset ((void *)key, 0, 32);

  // Allow the process to generate a core dump
  prctl (PR_SET_DUMPABLE, 1);

  // Free the memory
  free ((void *)key);
}
