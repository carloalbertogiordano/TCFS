#include "tcfs_helper_tools.h"
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @file user_tcfs.c
 * @brief Help the user that wants to use TCFS
 * */

/**
 * @internal
 * @var argp_program_version
 * @brief Program version. \_var
 * */
const char *argp_program_version = "TCFS user helper program";
/**
 * @internal
 * @var argp_program_bug_address
 * @brief Mail for bug reports. \_var
 * */
const char *argp_program_bug_address = "carloalbertogiordano@duck.com";
/**
 * @internal
 * @var doc
 * @brief Documentation for argp.\_var
 * */
static char doc[] = "TCFS user accepts one of three arguments: mount, "
                    "create-shared, or umount.";

/**
 * @internal
 * @var options
 * @brief Option accepted by tcfs helper program.\_var
 * */
static struct argp_option options[]
    = { { "mount", 'm', 0, 0, "Perform mount operation", -1 },
        { "create-shared", 'c', 0, 0, "Perform create-shared operation", -1 },
        { "umount", 'u', 0, 0, "Perform umount operation", -1 },
        { "setup-env", 's', 0, 0, "Perform the setup of the .tcfs folder",
          -1 },
        { NULL } };

/**
 * @struct arguments
 * @brief Structure to hold the parsed arguments
 * */
struct arguments
{
  int operation; /**< Decribes the operation that will be executed by the main
                    function */
};

/**
 * @internal
 * @brief Parse the operation, used by argp. \_func
 * @param key   The option character
 * @param arg   The argument string (unused)
 * @param state The state object of argp
 * @return static error_t   The error code (0 for success, ARGP_ERR_UNKNOWN for
 * unknown option)
 * */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  (void)arg;

  struct arguments *arguments = state->input;
  switch (key)
    {
    case 'm':
      arguments->operation = 1; // Mount
      break;
    case 'c':
      arguments->operation = 2; // Create-shared
      break;
    case 'u':
      arguments->operation = 3; // Umount
      break;
    case 's':
      arguments->operation = 4; // Set up the env
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

/**
 * @struct argp
 * @brief The struct used by argp
 * */
static struct argp argp = { .options = options,
                            .parser = parse_opt,
                            .doc = doc,
                            .args_doc = NULL,
                            .children = NULL,
                            .help_filter = NULL };

/**
 * @brief main function for the TCFS user helper program.
 * */
int
main (int argc, char *argv[])
{
  struct arguments arguments;
  arguments.operation = 0; // Default value
  int result = 0;

  // Parse the arguments
  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  switch (arguments.operation)
    {
    case 1:
      printf ("Mounting your FS, Please specify the location\n");
      result = do_mount ();
      if (result == 0)
        {
          fprintf (stderr, "An error occurred\n");
          exit (-1);
        }
      break;
    case 2:
      printf ("You chose the 'create-shared' operation.\n");
      // Add specific logic for 'create-shared' here.
      break;
    case 3:
      printf ("You chose the 'umount' operation.\n");
      // Add specific logic for 'umount' here.
      break;
    case 4:
      printf ("You chose the 'setup environment' option\n");
      result = setup_tcfs_env ();
      if (result == 0)
        {
          fprintf (stderr, "An error occurred\n");
          exit (-1);
        }
    default:
      printf ("Invalid argument. Choose from 'mount', 'create-shared', or "
              "'umount'.\n");
      return 1;
    }

  return 0;
}
