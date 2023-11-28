#include "tcfs_daemon_tools.h"
#include "../message_handler/message_handler.h"

/**
 * @file tcfs_daemon_tools.c
 * @brief This file contains the logic for handling the various requests and
 * responses on the message queue
 * */

/**
 * @brief Dequeue the latest message from the queue and handle it
 * @param queue_id  Pointer to mqd_t message queue descriptor
 * @return void
 * @note This function must never return. In case of its return the daemon will
 * stall
 * @todo Handle the case described in note
 * */
void *
handle_incoming_messages (void *queue_id)
{
  qm_type qmt;
  qm_user *user_msg;
  qm_shared *shared_msg;
  qm_broad *broadcast_msg;

  print_msg ("Starting handler for incoming messages");
  void *tmp_struct;
  while (1)
    {
      tmp_struct = dequeue (*(mqd_t *)queue_id, &qmt);
      switch (qmt)
        {
        case USER:
          print_msg ("Handling user message");
          user_msg = (qm_user *)tmp_struct;
          handle_user_message (user_msg);
          break;
        case SHARED:
          print_msg ("Handling shared message");
          shared_msg = (qm_shared *)tmp_struct;
          // handle_shared_message()
          break;
        case BROADCAST:
          print_msg ("Handling broadcast message");
          broadcast_msg = (qm_broad *)tmp_struct;
          // handle_broadcast_message()
          break;
        case QM_TYPE_UNDEFINED:
          print_err ("Received un unknown message type, skipping...");
          break;
        }
      free (tmp_struct);
    }
  return NULL;
}

/**
 * @brief Test if the daemon is working by sending some messages
 * @param queue_id  Pointer to mqd_t message queue descriptor
 * @return void
 * @note THIS FUNCTION IS HERE JUST TEMPORARILY. WILL BE REMOVED, THIS IS NOT
 * WHAT WE WANT THE DAEMON TO DO. PLEASE IGNORE
 * @todo Remove this function from the code
 * */
void *
handle_outgoing_messages (void *queue_id)
{
  print_msg ("Handling outgoing messages");
  // sleep(1);

  char s1[] = "TEST";
  char s2[] = "pubkey";

  struct qm_user test_msg;
  test_msg.user_op = REGISTER;
  test_msg.pid = 104;
  test_msg.user = s1;
  test_msg.pubkey = s2;

  print_msg ("Enqueueing test registration...");
  int res = enqueue (*(mqd_t *)queue_id, USER, (void *)&test_msg);
  print_msg ("TEST message send with result %d", res);

  if (res != 1)
    {
      print_err ("enqueue err ");
    }

  struct qm_user test_msg2;
  test_msg2.user_op = UNREGISTER;
  test_msg2.pid = 104;
  test_msg2.user = "";
  test_msg2.pubkey = "";

  sleep (3);

  print_msg ("Enqueueing test remove...");
  res = enqueue (*(mqd_t *)queue_id, USER, (void *)&test_msg2);
  print_msg ("TEST message send with result %d", res);

  if (res != 1)
    {
      print_err ("enqueue err ");
    }

  return NULL;
}

/*
 *
void* monitor_termination(void* queue_id) {
    while (1) {
        pthread_mutex_lock(&terminate_mutex);
        if (terminate) {
            pthread_mutex_unlock(&terminate_mutex);
            break;
        }
        pthread_mutex_unlock(&terminate_mutex);
        sleep(1);
    }
    print_err("Terminating threads");
    remove_empty_queue(*(int *)queue_id);
    return NULL;
}*/
