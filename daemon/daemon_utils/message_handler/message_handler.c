#include "message_handler.h"
#include "../common_utils/db/user_db.h"
#include "../common_utils/json/json_tools.h"
#include "../common_utils/print/print_utils.h"

int
handle_user_message (qm_user *user_msg)
{
  if (user_msg->user_op == REGISTER)
    {
      register_user (user_msg);
    }
  else if (user_msg->user_op == UNREGISTER)
    {
      unregister_user (user_msg->pid);
      // TODO: next line is a test, remove it
      free_context ();
    }
  else
    {
      print_err ("Unknown user operation %d", user_msg->user_op);
      return 0;
    }

  return 1;
}