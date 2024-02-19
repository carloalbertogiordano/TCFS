#include <stdbool.h>
#include "../debug_utils/debug_helper.h"

/**
 * @def DEFAULT_CONFIG_FILE
 * @brief The default location of the configuration file
 * */
#define DEFAULT_CONFIG_FILE "~/.tcfs/tcfs-config.yaml"

/**
* @struct config
* @brief Structure to store configuration settings.
*/
struct config {
  char *source; /**< Source path. */
  char *destination; /**< Destination path. */
  char *key_id; /**< Key ID. */
  char *password; /**<@deprecated Password (deprecated). */
  char *params; /**< Parameters to pass to FUSE. */
  DebugLevel debug; /**< Debug mode (true if enabled, false if disabled). */
  bool log_to_console; /**< Specify if the logging should be written to the console */
};

extern bool parse_config(const char *file_path, struct config *conf);