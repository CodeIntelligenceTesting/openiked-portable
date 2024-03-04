#include <pwd.h>
#include <unistd.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <event.h>

#include "fuzzdataprovider.h"
#include "iked.h"
#include "iked_env.h"

int LLVMFuzzerTestOneInput(const uint8_t *__data, size_t __size)
{
    FuzzDataProvider provider = FuzzDataConstruct(__data, __size);

    /* need to set global variable */
    struct iked *env = create_iked_env();
    iked_env = env;
    create_iked_env_aux(env);

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
    vroute_getaddr(env, &imsg);

    destroy_iked_env_aux(env);
    destroy_iked_env(env);
    iked_env = NULL;

    return 0;
}