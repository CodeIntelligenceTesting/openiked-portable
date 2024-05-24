#include <event.h> // used-by, but not included by <iked.h>

#include "cifuzz_bundled_config_embedded_blob.h"
#include "cifuzz_bundled_config_extract.h"
#include "cifuzz_bundled_config_prefix.h"
#include "ca.h"
#include "fuzzdataprovider.h"
#include "iked.h"
#include "cifuzz_iked_env.h"

#include "mocks/mocks.h"

#include "fuzzer_utils/ca_utils.c"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    printf("%s:%d: Restoring bundled configuration...\n", __FILE__, __LINE__);
    cifuzz_bundled_config_extract(
        cifuzz_bundled_config_prefix(),
        cifuzz_bundled_config_embedded_blob(),
        cifuzz_bundled_config_embedded_blob_size()
    );

    copy_all_files();
    return 0;

}

int LLVMFuzzerTestOneInput(const uint8_t *__data, size_t __size)
{
    FuzzDataProvider provider = FuzzDataConstruct(__data, __size);

    struct iked *env = cifuzz_create_iked_env();
    iked_env = env;
    cifuzz_create_iked_env_aux(env);
    config_setkeys(env);
    ca_reset(NULL);
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

    ca_dispatch_ikev2(-1, NULL, &imsg);

    free(payload);
    cifuzz_destroy_iked_env_aux(env);
    cifuzz_destroy_iked_env(env);
    event_base_free(NULL);
    iked_env = NULL;

    return 0;
}
