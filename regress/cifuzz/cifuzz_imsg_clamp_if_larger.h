#include <stddef.h>

#include <event.h> // used-by, but not included by <iked.h>

#include "iked.h"

#ifdef __cplusplus
extern "C" {
#endif

/***
 * Auxiliary function that truncates @arg imsg to @arg max_payload_length
 */
void cifuzz_imsg_clamp_if_larger(struct imsg *imsg, size_t max_payload_length);

#ifdef __cplusplus   
}
#endif