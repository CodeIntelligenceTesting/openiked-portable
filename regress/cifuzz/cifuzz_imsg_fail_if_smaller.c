#include "cifuzz_imsg_clamp_if_larger.h"

int cifuzz_imsg_fail_if_smaller(struct imsg *imsg, uint32_t min_payload_length)
{
    if (imsg->hdr.len >= sizeof(struct imsg_hdr) + min_payload_length) {
        return EXIT_SUCCESS;
    } else {
        return EXIT_FAILURE;
    }
}