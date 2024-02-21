/**
 * @file yaml-loader.h
 * @brief This file contains functions for parsing YAML configuration files.
 */

#include "yaml_loader.h"
#include "../tcfs_utils/tcfs_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>

/**
 * @brief Parse YAML configuration file.
 *
 * This function parses the specified YAML file and populates the given config
 * structure with the settings.
 *
 * @param file_path Path to the YAML configuration file.
 * @param conf Pointer to the config structure to be populated.
 * @return true on success, false on failure.
 */
bool
parse_config (const char *file_path, struct config *conf)
{
  FILE *file;
  yaml_parser_t parser;
  yaml_event_t event;
  char *key = NULL;
  bool value_next = false;
  const char *expanded_path = NULL;

  expanded_path = expand_path (file_path);
  file = fopen (expanded_path, "rb");
  free ((void *)expanded_path);

  if (!file)
    {
      logErr ("Failed to open logfile");
      return false;
    }

  if (!yaml_parser_initialize (&parser))
    {
      logErr ("Failed to initialize the YAML parser");
      return false;
    }

  yaml_parser_set_input_file (&parser, file);

  while (1)
    {
      if (!yaml_parser_parse (&parser, &event))
        {
          yaml_parser_delete (&parser);
          return false;
        }

      if (event.type == YAML_SCALAR_EVENT)
        {
          if (value_next)
            {
              if (strcmp (key, "source") == 0)
                {
                  conf->source = strdup ((char *)event.data.scalar.value);
                }
              else if (strcmp (key, "destination") == 0)
                {
                  conf->destination = strdup ((char *)event.data.scalar.value);
                }
              else if (strcmp (key, "key_id") == 0)
                {
                  conf->key_id = strdup ((char *)event.data.scalar.value);
                }
              else if (strcmp (key, "params") == 0)
                {
                  conf->params = strdup ((char *)event.data.scalar.value);
                }
              else if (strcmp (key, "debug") == 0)
                {
                  if (strcmp ((char *)event.data.scalar.value, "DEBUG_ALL")
                      == 0)
                    {
                      conf->debug = DEBUG_ALL;
                    }
                  else if (strcmp ((char *)event.data.scalar.value,
                                   "DEBUG_CALLS")
                           == 0)
                    {
                      conf->debug = DEBUG_CALLS;
                    }
                  else if (strcmp ((char *)event.data.scalar.value,
                                   "DEBUG_ERRORS")
                           == 0)
                    {
                      conf->debug = DEBUG_ERRORS;
                    }
                  else
                    {
                      conf->debug = DEBUG_NONE;
                    }
                }
              else if (strcmp (key, "log_to_console") == 0)
                {
                  if (strcmp ((char *)event.data.scalar.value, "true") == 0)
                    {
                      conf->log_to_console = true;
                    }
                  else
                    {
                      conf->log_to_console = false;
                    }
                }
              value_next = false;
            }
          else
            {
              key = strdup ((char *)event.data.scalar.value);
              value_next = true;
            }
        }

      if (event.type == YAML_STREAM_END_EVENT)
        {
          break;
        }

      yaml_event_delete (&event);
    }

  yaml_parser_delete (&parser);
  fclose (file);

  return true;
}
