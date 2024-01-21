#include "tcfs_helper_tools.h"

/**
 * @file tcfs_helper_tools.c
 * @brief This file contains the logic and implementation of functions needed to perform the operations requested in user_tcfs.c
 * \see user_tcfs.c
 * */

/**
 * @internal
 * @def PASS_SIZE
 * @brief Set the password size to 33 as AES 256 uses a 32 byte key. An \0 is added for safety. \_def
 * */
#define PASS_SIZE 33

int handle_local_mount ();
int handle_remote_mount ();
int handle_folder_mount ();

/**
 * @brief Execute the mount of either a Network FS (for ex NFS), Local FS (for ex a block device), Local folder (a folder of the system)
 * @return \_ret
 * */
int
do_mount ()
{
  int choice = -1;
  do
    {
      printf ("Chose between:\n"
              "\t1. Network FS\n"
              "\t2. Local FS\n"
              "\t3. Local folder");
      scanf ("%d", &choice);
      if (choice != 1 && choice != 2 && choice != 3)
        printf ("Err: Select 1 or 2\n");
    }
  while (choice != 1 && choice != 2 && choice != 3);
  printf ("You chose %d\n", choice);

  if (choice == 1)
    {
      return handle_remote_mount ();
    }
  else if (choice == 2)
    {
      return handle_local_mount ();
    }
  else if (choice == 3)
    {
      return handle_folder_mount ();
    }
  printf ("Unrecoverable error\n");
  return 0;
}

/**
 * @internal
 * @brief Generate a random string that will be used as a folder name for the mount. \_func
 * @param str   The result will be saved here
 * @return int  \_ret
 * */
int
generate_random_string (char *str)
{
  srand (time (NULL));
  if (str == NULL)
    return 0;
  for (int i = 0; i < 10; i++)
    str[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        [rand () % 62];
  str[10] = '\0';
  return 1;
}

/**
 * @internal
 * @brief Check if a directory already exists. \_func
 * @param path  Fullpath to the dir
 * @return int  \_ret
 * */
int
directory_exists (const char *path)
{
  struct stat sb;
  return stat (path, &sb) == 0 && S_ISDIR (sb.st_mode);
}

/**
 * @internal
 * @brief Creates the .tcfs folder in the user HOME. Then this creates a folder with a random name so that create_tcfs_mount_local_folder function can use it. \ref create_tcfs_mount_local_folder \_func
 * @return a folder with a random name inside the $HOME/.tcfs folder
 * */
char *
setup_tcfs_mount_folder ()
{
  printf ("SETUP ENV\n");
  char *home = getenv ("HOME");
  printf ("$HOME=%s\n", home);

  char *tcfs_path
      = malloc ((strlen (home) + strlen ("/.tcfs\0")) * sizeof (char));
  char rand_path_name[11];
  char *new_path = NULL;

  if (home == NULL)
    {
      perror ("Could not get $HOME\n");
      return 0;
    }

  if (tcfs_path == NULL)
    {
      perror ("Could not allocate string tcfs_path");
      return 0;
    }
  sprintf (tcfs_path, "%s/%s", home, ".tcfs");

  //$HOME/.tcfs does not exist if this is true
  if (directory_exists (tcfs_path) == 0)
    {
      if (mkdir (tcfs_path, 0770) == -1)
        {
          perror ("Cannot create .tcfs directory");
          return 0;
        }
    }
  // Create a folder to mount the source to
  // Generate a random path name
  if (generate_random_string (rand_path_name) == 0)
    {
      fprintf (stderr, "Err: Name generation for temp folder failed\n");
      return 0;
    }
  // Build the path from / to the generated path
  new_path = malloc ((strlen (rand_path_name) + strlen (tcfs_path) + 1)
                     * sizeof (char));
  if (new_path == NULL)
    {
      perror ("Cannot allocate new memory for path name");
      return 0;
    }
  sprintf (new_path, "%s/%s", tcfs_path, rand_path_name);
  if (mkdir (new_path, 0770) == -1)
    {
      perror ("Cannot create the tmp folder inside .tcfs");
      return 0;
    }

  printf ("New path %s\n", new_path);
  free (tcfs_path);
  return new_path;
}

/**
 * @internal
 * @brief fetch the password of the current user. \_func
 * @param pw    String to save the password to
 * @todo This will be changed when a public/private key model will be avilable to TCFS userspace module
 * */
void
get_pass (char *pw)
{
  struct termios old, new;
  int i = 0;
  int ch = 0;

  // Disable character echo
  tcgetattr (STDIN_FILENO, &old);
  new = old;
  new.c_lflag &= ~ECHO;
  tcsetattr (STDIN_FILENO, TCSANOW, &new);

  printf ("Please enter a password exactly %d characters long:\n", PASS_SIZE);

  while (strlen (pw) * sizeof (char) < (PASS_SIZE - 1) * sizeof (char))
    {
      while (1)
        {
          ch = getchar ();
          if (ch == '\r' || ch == '\n' || ch == EOF)
            {
              break;
            }
          if (i < PASS_SIZE - 1)
            {
              pw[i] = ch;
              pw[i + 1] = '\0';
            }
          i++;
        }
    }

  // Restore terminal settings
  tcsetattr (STDIN_FILENO, TCSANOW, &old);
  printf ("\nPassword successfully entered!\n");
}

/**
 * @internal
 * @param Ask the user to insert the source and the destination of the mount. \_func
 * */
void
get_source_dest (char *source, char *dest)
{
  printf ("Please type the path to the source\n");
  scanf ("%s", source);

  printf ("Please type where it should be mounted\n");
  scanf ("%s", dest);
}

/**
 * @internal
 * @brief Create a temporary folder in HOME/.tcfs
 * @return char * the fullpath to the generated folder
 * */
char *
create_tcfs_mount_local_folder ()
{
  char *tmp_path = NULL;

  // Create a folder to mount to
  tmp_path = setup_tcfs_mount_folder ();
  if (tmp_path == NULL)
    {
      fprintf (stderr, "Err: could not get temp path\n");
      return NULL;
    }
  printf ("Creating dir: %s\n", tmp_path);
  return tmp_path;
}

int
mount_tcfs_folder (char *tmp_path, char *destination)
{
  char pass[PASS_SIZE] = "\0";
  struct termios old, new;

  // Disable character echo
  tcgetattr (STDIN_FILENO, &old);
  new = old;
  new.c_lflag &= ~ECHO;
  tcsetattr (STDIN_FILENO, TCSANOW, &new);

  get_pass (pass);
  if (pass[0] == '\0')
    {
      tcsetattr (STDIN_FILENO, TCSANOW, &old);
      fprintf (stderr, "Could not get password\n");
      return 0;
    }

  // Mount tmpfolder to the destination
  char *tcfs_command
      = malloc ((strlen ("tcfs -s ") + strlen (tmp_path) + strlen (" -d ")
                 + strlen (destination) + strlen (" -p ") + strlen (pass)));
  sprintf (tcfs_command, "tcfs -s %s -d %s -p %s", tmp_path, destination,
           pass);

  int status_tcfs_mount = system (tcfs_command);
  if (!(WIFEXITED (status_tcfs_mount) && WEXITSTATUS (status_tcfs_mount) == 0))
    {
      tcsetattr (STDIN_FILENO, TCSANOW, &old);
      perror ("Could not execute the command");
      return 0;
    }
  free (tcfs_command);
  tcsetattr (STDIN_FILENO, TCSANOW, &old);
  return 1;
}

int
handle_local_mount ()
{
  char source[PATH_MAX];
  char destination[PATH_MAX];
  char *tmp_path = NULL;

  get_source_dest (source, destination);

  tmp_path = create_tcfs_mount_local_folder ();
  if (tmp_path == NULL)
    {
      printf ("Err: could not get tmp folder path\n");
      return 0;
    }

  // Mount block device to temp folder
  char *command = malloc (
      (strlen ("mount ") + strlen (source) + strlen (" ") + strlen (tmp_path))
      * sizeof (char));
  if (command == NULL)
    {
      perror ("cannot allocate memoty for the command");
      return 0;
    }
  sprintf (command, "sudo mount -o umask=0755,gid=1000,uid=1000 %s %s", source,
           tmp_path);
  printf ("executing: %s\n", command);
  int status_tmp_mount = system (command);
  if (!(WIFEXITED (status_tmp_mount) && WEXITSTATUS (status_tmp_mount) == 0))
    {
      perror ("Could not execute the command");
      return 0;
    }

  int res = mount_tcfs_folder (tmp_path, destination);
  if (res == 0)
    return 0;

  free (tmp_path);
  free (command);
  return 1;
}

int
handle_folder_mount ()
{
  char source[PATH_MAX];
  char destination[PATH_MAX];

  get_source_dest (source, destination);
  if (source[0] == '\0' || destination[0] == '\0')
    {
      printf ("Err: Could not get source or destination\n");
      return 0;
    }
  printf ("Source:%s\tdestination:%s\n", source, destination);

  int res = mount_tcfs_folder (source, destination);
  if (res == 0)
    return 0;

  return 1;
}

void
clearKeyboardBuffer ()
{
  int ch;
  while ((ch = getchar ()) != EOF && ch != '\n')
    ;
}

int
handle_remote_mount ()
{
  char source[PATH_MAX] = "\0";
  char destination[PATH_MAX] = "\0";
  char command[100] = "\0";

  printf ("WARN: This function is not complete, I don't know how many remote "
          "FileSystems support extended "
          "attributes, please mount it manually. "
          "\nEX:sudo mount -t nfs -o umask=0755,gid=1000,uid=1000 "
          "10.10.10.10:/NFS /mnt\n");

  clearKeyboardBuffer ();
  printf ("Enter the command: ");
  int ch;
  int loop = 0;
  while (loop < 99 && (ch = getc (stdin)) != EOF && ch != '\n')
    {
      command[loop] = ch;
      ++loop;
    }
  command[loop] = '\0'; // Null-terminate the string

  printf ("Command: %s\n", command);
  int status = system (command);
  if (!(WIFEXITED (status) && WEXITSTATUS (status) == 0))
    {
      perror ("Could not execute the command");
      return 0;
    }

  printf ("Where has it been mounted? ");
  loop = 0;
  while (loop < PATH_MAX - 1 && (ch = getc (stdin)) != EOF && ch != '\n')
    {
      source[loop] = ch;
      ++loop;
    }
  source[loop] = '\0'; // Null-terminate the string

  printf ("Source: %s\n", source);

  printf ("Where should TCFS mount it? ");
  loop = 0;
  while (loop < PATH_MAX - 1 && (ch = getc (stdin)) != EOF && ch != '\n')
    {
      destination[loop] = ch;
      ++loop;
    }
  destination[loop] = '\0'; // Null-terminate the string

  printf ("Destination: %s\n", destination);

  int res = mount_tcfs_folder (source, destination);
  return res;
}

int
setup_tcfs_env ()
{
  return 0;
}