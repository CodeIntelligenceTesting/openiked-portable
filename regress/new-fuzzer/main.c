#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <event.h>

#include "iked.h"

int LLVMFuzzerTestOneInput(const char *data, size_t size)
{
    struct iked env;
	struct ike_header hdr;
    struct iked_message msg;
    struct iked_sa sa;

    struct ibuf *buf = ibuf_new(data, size);

    memset(&env, 0, sizeof(env));
    memset(&sa, 0, sizeof(sa));
    memset(&msg, 0, sizeof(msg));

	msg.msg_sa = &sa;
	msg.msg_data = buf;
	msg.msg_e = 1;
	msg.msg_parent = &msg;

    ikev2_pld_parse(&env, &hdr, &msg, 0);

    ibuf_free(buf);

    return 0;
}