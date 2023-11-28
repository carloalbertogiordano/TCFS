#include "queue.h"

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