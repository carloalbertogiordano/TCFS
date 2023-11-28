#include "../../common.h"

extern const char *struct_to_json (qm_type qmt, void *q_mess);
extern void *string_to_struct (const char *json_string, qm_type *type);