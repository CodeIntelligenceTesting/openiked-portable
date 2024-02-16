#include <stddef.h>
#include <string.h>

#include <event.h>

#include "fuzzdataprovider.h"
#include "iked.h"

int LLVMFuzzerTestOneInput(const uint8_t *__data, size_t __size)
{
    FuzzDataProvider provider = FuzzDataConstruct(__data, __size);

    struct iked env;
    memset(&env, 0, sizeof(env));

    typedef struct {
        struct sockaddr addr;
        struct sockaddr mask;
        unsigned int ifidx;
    } vroute_getaddr_data_t;

    vroute_getaddr_data_t vroute_getaddr_data = {
        .addr = FuzzDataReadSockAddr(&provider),
        .mask = FuzzDataReadSockAddr(&provider),
        .ifidx = FuzzDataReadUint32(&provider)
    };

    struct imsg imsg = {
        .hdr = {
            .type = FuzzDataReadUint32(&provider),
	        .len = sizeof(struct imsg_hdr) + /* sizeof(int) */ + sizeof(vroute_getaddr_data_t),
            .flags = FuzzDataReadUint16(&provider),
            .peerid = FuzzDataReadUint32(&provider),
            .pid = FuzzDataReadUint32(&provider)
        },
        .fd = -1,
        .data = &vroute_getaddr_data
    };
    vroute_getaddr(&env, &imsg);

    return 0;
}