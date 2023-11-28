#include "../message_handler/message_handler.h"
#include "../queue/queue.h"
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

// Condition variable & mutex
extern volatile int terminate;
extern pthread_mutex_t terminate_mutex;

void *handle_incoming_messages (void *queue_id);
void *handle_outgoing_messages (void *queue_id);
void *monitor_termination (void *queue_id);
void cleanup_threads (pthread_t thread1, pthread_t thread2);