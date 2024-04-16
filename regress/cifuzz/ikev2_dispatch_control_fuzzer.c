#include <event.h> // used-by, but not included by <iked.h>

#include "cifuzz_bundled_config_embedded_blob.h"
#include "cifuzz_bundled_config_extract.h"
#include "cifuzz_bundled_config_prefix.h"
#include "fuzzdataprovider.h"
#include "iked.h"
#include "cifuzz_iked_env.h"

/*
 * not exported symbol from
 *   https://github.com/openiked/openiked-portable/blob/6d5b015f50301ffb1800f36f636b953a714c9e62/iked/ikev2.c#L69
 */
extern int	 ikev2_dispatch_control(int, struct privsep_proc *, struct imsg *);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    printf("%s:%d: Restoring bundled configuration...\n", __FILE__, __LINE__);
    cifuzz_bundled_config_extract(
        cifuzz_bundled_config_prefix(),
        cifuzz_bundled_config_embedded_blob(),
        cifuzz_bundled_config_embedded_blob_size()
    );
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *__data, size_t __size)
{
    FuzzDataProvider provider = FuzzDataConstruct(__data, __size);

    /* need to set global variable */
    struct iked *env = cifuzz_create_iked_env();
    iked_env = env;
    cifuzz_create_iked_env_aux(env);

    struct imsg imsg = {
        .hdr = {
            .type = FuzzDataReadUint32(&provider),
            .len = sizeof(struct imsg_hdr),
            .flags = FuzzDataReadUint16(&provider),
            .peerid = FuzzDataReadUint32(&provider),
            .pid = FuzzDataReadUint32(&provider)
        },
        .fd = -1,
        .data = NULL
    };

    size_t payload_length = FuzzDataBytesRemaining(&provider);
    uint8_t *payload = FuzzDataReadByteArray(&provider, payload_length);

    imsg.hdr.len += payload_length;
    imsg.data = payload;

    ikev2_dispatch_control(-1, NULL, &imsg);

    free(payload);

    cifuzz_destroy_iked_env_aux(env);
    cifuzz_destroy_iked_env(env);
    iked_env = NULL;

    return 0;
}
