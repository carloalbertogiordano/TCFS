#include "user_db.h"
#include "redis.h"

/**
 * @file user_db.c
 * @brief This file contains the functions to interact with the database
 * */

/**
 * @brief Register or update a user in the db, this relies on the redis.c file
 * @param \p_qmu
 * @return \ret
 * */
int
register_user (qm_user *user_msg)
{
  print_msg ("Registering new user");
  if (init_context () == 0)
    return 0;
  print_all_keys ();
  if (insert (user_msg) == 0)
    return 0;
  return 1;
}
/**
 * @brief Remove a user from the DB
 * @param pid_t pid     the key
 * @return \ret
 * */
int
unregister_user (pid_t pid)
{
  print_all_keys ();
  print_msg ("Removing user");
  return remove_by_pid (pid);
}
/**
 * @brief Free the context of the DB
 * @param void
 * @return void
 * @note If this fails no errors will be printed and no errno will be set, you
 * are on your own :(
 * */
void
disconnect_db (void)
{
  print_msg ("Freeing context...");
  free_context ();
}