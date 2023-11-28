#include "../common.h"
#include "../common_utils/json/json_tools.h"
#include "../common_utils/print/print_utils.h"
#include <stdio.h>
#include <stdlib.h>

mqd_t init_queue (char *queue);
int enqueue (mqd_t queue_d, qm_type qmt, void *q_mess);
void *dequeue (mqd_t queue_d, qm_type *qmt);