#include "tcfs_helper_tools.h"
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>

// Define the program documentation
const char *argp_program_version = "TCFS user helper program";
const char *argp_program_bug_address = "carloalbertogiordano@duck.com";
static char doc[] = "TCFS user accepts one of three arguments: mount, "
                    "create-shared, or umount.";

// Define the accepted options
static struct argp_option options[]
    = { { "mount", 'm', 0, 0, "Perform mount operation", -1 },
        { "create-shared", 'c', 0, 0, "Perform create-shared operation", -1 },
        { "umount", 'u', 0, 0, "Perform umount operation", -1 },
        { NULL } };

// Structure to hold the parsed arguments
struct arguments
{
  int operation;
};

// Parse the arguments
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
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

// Define the argp object
static struct argp argp = { .options = options,
                            .parser = parse_opt,
                            .doc = doc,
                            .args_doc = NULL,
                            .children = NULL,
                            .help_filter = NULL };

int
main (int argc, char *argv[])
{
  struct arguments arguments;
  arguments.operation = 0; // Default value

  // Parse the arguments
  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  arguments.operation = 1; // TODO: option 1 is the only one implemented
  switch (arguments.operation)
    {
    case 1:
      printf ("Mounting your FS, Please specify the location\n");
      int result = do_mount ();
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
    default:
      printf ("Invalid argument. Choose from 'mount', 'create-shared', or "
              "'umount'.\n");
      return 1;
    }

  return 0;
}
