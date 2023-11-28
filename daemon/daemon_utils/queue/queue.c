#include "queue.h"

/**
 * @file queue.c
 * @brief This file contains the implementation of a "facade pattern" for
 * handling the queue in an easier way
 * */

/**
 * @def MESSAGE_BUFFER_SIZE
 * @brief This defines the max size of a message on the queue. \_def
 * */
#define MESSAGE_BUFFER_SIZE 256
/**
 * @def MQUEUE_N
 * @brief Max number of messages on a queue. \def
 * */
#define MQUEUE_N 256;

/**
 * @brief Initialize the message queue
 * @param queue the path of the queue file
 * @return mqd_t  Message queue descriptor
 * @todo Define permissions for mq_open
 * */
mqd_t
init_queue (char *queue)
{
  struct mq_attr attr;
  mqd_t mq;

  // Initialize queue attributes
  attr.mq_flags = 0;
  attr.mq_maxmsg = MAX_QM_N;     // Maximum number of messages in the queue
  attr.mq_msgsize = MAX_QM_SIZE; // Maximum size of a single message
  attr.mq_curmsgs = 0;

  // Create the message queue
  mq = mq_open (queue, O_CREAT | O_RDWR /*| O_RDONLY | O_NONBLOCK*/, 0777,
                &attr); // TODO: Better define permissions
  printf ("mqopen %d\n", mq);
  if (mq == (mqd_t)-1)
    {
      print_err ("mq_open cannot create que in %s %d %s", queue, errno,
                 strerror (errno));
      print_msg ("mq_open cannot create que in %s %d %s", queue, errno,
                 strerror (errno));
      return 0;
    }
  printf ("Message queue created successfully at %s!\n", queue);
  return mq;
}

/**
 * @brief Enqueues a message void* message on the queue
 * @param queue_d  Message queue descriptor type
 * @param qmt enum describing the type of the message. \see qm_type
 * @param q_mess  Actual message, this must be either \n
 * qm_user, qm_shared qm_broad
 * \see qm_user \see qm_shared \n  \see qm_broad
 * @return \ret
 * @note The structure representing the message will be casted to a json and
 * then it will be enqueued
 * */
int
enqueue (mqd_t queue_d, qm_type qmt, void *q_mess)
{
  const char *qm_json = struct_to_json (qmt, q_mess);

  if (mq_send (queue_d, qm_json, strlen (qm_json) + 1, 0) == -1)
    {
      print_err ("mq_send %s", qm_json);
      free ((void *)qm_json);
      return 0;
    }
  print_msg ("Message sent successfully!\n");
  free ((void *)qm_json);
  return 1;
}

/**
 * @brief Dequeue a message from the queue and get is as a void* pointing to a
 * structure that will be either \n qm_user \see qm_user \n qm_shared \see
 * qm_shared \n qm_broad \see qm_broad \n qm_type *qmt will be set to the
 * corresponding type. You can yse this value to cast the returned value back
 * to a structure
 * @param queue_d Message queue descriptor type
 * @param qmt  Pointer to a struct indicating the type of the returned
 * parameter \see qm_type
 * @return A pointer to a structure containing the structured message data. If
 * an error occurs NULL is returned
 * */
void *
dequeue (mqd_t queue_d, qm_type *qmt)
{
  char *qm_json = (char *)malloc (sizeof (char) * MAX_QM_SIZE);

  if (mq_receive (queue_d, qm_json, MAX_QM_SIZE, 0) == -1)
    {
      free ((void *)qm_json);
      print_err ("mq_rec %d %s", errno, strerror (errno));
      return NULL;
    }

  print_msg ("Dequeued %s", qm_json);
  void *tmp_struct = string_to_struct (qm_json, qmt);

  free ((void *)qm_json);
  return tmp_struct;
}