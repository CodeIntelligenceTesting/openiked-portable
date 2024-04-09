#include <event.h> // used-by, but not included by <iked.h>

#include "cifuzz_bundled_config_embedded_blob.h"
#include "cifuzz_bundled_config_extract.h"
#include "cifuzz_bundled_config_prefix.h"
#include "cifuzz_imsg_clamp_if_larger.h"
#include "cifuzz_imsg_fail_if_smaller.h"
#include "ca.h"
#include "fuzzdataprovider.h"
#include "iked.h"
#include "iked_env.h"

struct cifuzz_ocsp_connect_payload
{
    struct iked_sahdr sh;
};

union cifuzz_IMGS_payload
{
    struct cifuzz_ocsp_connect_payload oscp_connect;
};

int cifuzz_check_message_payload(struct imsg *imsg)
{
    union cifuzz_IMGS_payload *blob = (union cifuzz_IMGS_payload*)(imsg->data);

    switch (imsg->hdr.type) {
	case IMSG_OCSP_FD:
        return cifuzz_imsg_fail_if_smaller(imsg, sizeof(blob->oscp_connect));
    }
    return EXIT_FAILURE;
}

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
    struct iked *env = create_iked_env();
    iked_env = env;
    create_iked_env_aux(env);

    struct imsg imsg = {
        .hdr = {
            .type = IMSG_OCSP_FD,
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

    if (cifuzz_check_message_payload(&imsg) == EXIT_SUCCESS) {
        ocsp_connect(env, &imsg);
    }

    free(payload);

    destroy_iked_env_aux(env);
    destroy_iked_env(env);
    iked_env = NULL;

    return 0;
}
