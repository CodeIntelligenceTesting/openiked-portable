#include <stddef.h>

#include <event.h> // used-by, but not included by <iked.h>

#include "iked.h"

#ifdef __cplusplus
extern "C" {
#endif

/***
 * Compare @arg imsg's size to to @arg min_payload_length
 * @return EXIT_SUCCESS if imsg is at least min_payload_length
 */
int cifuzz_imsg_fail_if_smaller(struct imsg *imsg, uint32_t min_payload_length);

#ifdef __cplusplus   
}
#endif