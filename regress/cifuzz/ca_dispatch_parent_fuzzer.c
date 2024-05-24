#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#include <event.h> // used-by, but not included by <iked.h>

#include "cifuzz_bundled_config_embedded_blob.h"
#include "cifuzz_bundled_config_extract.h"
#include "cifuzz_bundled_config_prefix.h"
#include "cifuzz_imsg_clamp_if_larger.h"
#include "cifuzz_imsg_fail_if_smaller.h"
#include "fuzzdataprovider.h"
#include "iked.h"
#include "cifuzz_iked_env.h"
#include "ca.h"
#include "mocks/mocks.h"
#include "fuzzer_utils/ca_utils.c"


struct cifuzz_IMSG_CTL_RESET_payload
{
    unsigned int mode;
};

struct cifuzz_IMSG_OCSP_FD_payload
{
    struct iked_sahdr sh;
};

struct cifuzz_IMSG_OCSP_CFG_payload
{
    long sc_ocsp_tolerate;
	long sc_ocsp_maxage;
    char sc_ocsp_url[0]; /* can have any length */
};

struct cifuzz_IMSG_PRIVKEY_payload
{
    struct iked_id id;
};

struct cifuzz_IMSG_CERT_PARTIAL_CHAIN_payload
{
    unsigned int boolval;
};

union cifuzz_IMGS_payload
{
    struct cifuzz_IMSG_CTL_RESET_payload ctl_reset;
    struct cifuzz_IMSG_OCSP_FD_payload ocsp_fd;
    struct cifuzz_IMSG_OCSP_CFG_payload ocsp_cfg;
    struct cifuzz_IMSG_PRIVKEY_payload privkey;
    struct cifuzz_IMSG_PRIVKEY_payload pubkey;
    struct cifuzz_IMSG_CERT_PARTIAL_CHAIN_payload cert_partial_chain;
};

int cifuzz_check_message_payload(struct imsg *imsg)
{
    union cifuzz_IMGS_payload *blob = (union cifuzz_IMGS_payload*)(imsg->data);

    switch (imsg->hdr.type) {
	case IMSG_CTL_RESET:
        // this crashes
        //return cifuzz_imsg_fail_if_smaller(imsg, sizeof(blob->ctl_reset));

	case IMSG_OCSP_FD:
        return cifuzz_imsg_fail_if_smaller(imsg, sizeof(blob->ocsp_fd));

	case IMSG_OCSP_CFG:
        return cifuzz_imsg_fail_if_smaller(imsg, sizeof(blob->ocsp_cfg));

	case IMSG_PRIVKEY:
	case IMSG_PUBKEY:
        // this crashes
        //return cifuzz_imsg_fail_if_smaller(imsg, sizeof(blob->privkey));
        return EXIT_FAILURE;

	case IMSG_CERT_PARTIAL_CHAIN:
		return cifuzz_imsg_fail_if_smaller(imsg, sizeof(blob->cert_partial_chain));

	default:
		return EXIT_SUCCESS;
	}
}

/*
 * not exported symbol from
 *   https://github.com/openiked/openiked-portable/blob/6d5b015f50301ffb1800f36f636b953a714c9e62/iked/ca.c#L87
 */
extern int	 ca_dispatch_parent(int, struct privsep_proc *, struct imsg *);

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

    /* need to set global variable */
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

    if (cifuzz_check_message_payload(&imsg) == EXIT_SUCCESS) {
        ca_dispatch_parent(-1, NULL, &imsg);
    }
    free(payload);

    cifuzz_destroy_iked_env_aux(env);
    cifuzz_destroy_iked_env(env);
    event_base_free(NULL);
    iked_env = NULL;

    return 0;
}
