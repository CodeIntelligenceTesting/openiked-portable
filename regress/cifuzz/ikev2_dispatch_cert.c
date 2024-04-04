#include <event.h> // used-by, but not included by <iked.h>

#include "bundled_config_extract.h"
#include "bundled_config_prefix.h"
#include "fuzzdataprovider.h"
#include "iked.h"
#include "iked_env.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    printf("%s:%d: Restoring bundled configuration...\n", __FILE__, __LINE__);
    cifuzz_bundled_config_extract(bundled_config_prefix());
    return 0;
}

extern int ikev2_dispatch_cert(int fd, struct privsep_proc *p, struct imsg *imsg);

int LLVMFuzzerTestOneInput(const uint8_t *__data, size_t __size)
{
    FuzzDataProvider provider = FuzzDataConstruct(__data, __size);

    /* need to set global variable */
    struct iked *env = create_iked_env();
    iked_env = env;
    create_iked_env_aux(env);

    typedef struct {
        struct iked_sahdr sh;
        uint8_t type;
    } ikev2_getimsgdata_data_t;

    typedef struct {
        uint8_t type;
    } IMSG_CERTREQ_data_t;

    /*
     * most of the functions consume the same amount of data, but let's name them explicitly nevertheless
     */
    typedef struct {
        ikev2_getimsgdata_data_t ikev2_getimsgdata_data;
    } IMSG_CERTVALID_data_t, IMSG_CERTINVALID_data_t,
      IMSG_CERT_data_t,
      IMSG_SCERT_data_t,
      IMSG_AUTH_data_t;

    typedef struct {
        /* does not read data*/
    } default_data_t;

    typedef union {
        IMSG_CERTREQ_data_t IMSG_CERTREQ_data;
        IMSG_CERTVALID_data_t IMSG_CERTVALID_data;
        IMSG_CERTINVALID_data_t IMSG_CERTINVALID_data;
        IMSG_CERT_data_t IMSG_CERT_data;
        IMSG_SCERT_data_t IMSG_SCERT_data;
        IMSG_AUTH_data_t IMSG_AUTH_data;
        default_data_t default_data;
    } ikev2_dispatch_cert_data_t;

    ikev2_dispatch_cert_data_t payload;
    size_t payload_length = 0;
    uint32_t imsg_type = FuzzDataReadUint32(&provider);

    switch(imsg_type)
    {
        case IMSG_CERTREQ:
            payload_length = sizeof(payload.IMSG_CERTREQ_data);
            FuzzDataReadIntoByteArray(&provider, (uint8_t *)(&payload.IMSG_CERTREQ_data), payload_length);
            break;
        case IMSG_CERTVALID:
            payload_length = sizeof(payload.IMSG_CERTVALID_data);
            FuzzDataReadIntoByteArray(&provider, (uint8_t *)(&payload.IMSG_CERTVALID_data), payload_length);
        case IMSG_CERTINVALID:
            payload_length = sizeof(payload.IMSG_CERTINVALID_data);
            FuzzDataReadIntoByteArray(&provider, (uint8_t *)(&payload.IMSG_CERTINVALID_data), payload_length);
            break;
        case IMSG_CERT:
            payload_length = sizeof(payload.IMSG_CERT_data);
            FuzzDataReadIntoByteArray(&provider, (uint8_t *)(&payload.IMSG_CERT_data), payload_length);
            break;
        case IMSG_SCERT:
            payload_length = sizeof(payload.IMSG_SCERT_data);
            FuzzDataReadIntoByteArray(&provider, (uint8_t *)(&payload.IMSG_SCERT_data), payload_length);
            break;
        case IMSG_AUTH:
            payload_length = sizeof(payload.IMSG_AUTH_data);
            FuzzDataReadIntoByteArray(&provider, (uint8_t *)(&payload.IMSG_AUTH_data), payload_length);
            break;
        default:
            payload_length = sizeof(payload.default_data);
            FuzzDataReadIntoByteArray(&provider, (uint8_t *)(&payload.default_data), payload_length);
            break;
    }

    struct imsg imsg = {
        .hdr = {
            .type = imsg_type,
            .len = sizeof(struct imsg_hdr) + payload_length,
            .flags = FuzzDataReadUint16(&provider),
            .peerid = FuzzDataReadUint32(&provider),
            .pid = FuzzDataReadUint32(&provider)
        },
        .fd = -1,
        .data = &payload
    };

    /*
     * TODO
     * in addition to the data in imsg, ikev2_dispatch_cert also receives data via the
     * iked_env environment variable.
     *
     *  [1] iked::sc_sas is referenced by 
     *      https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/policy.c#L827
     *      invoked by
     *      + https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/ikev2.c#L622
     *
     *  [2] iked::sc_stats is referenced by
     *      https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/iked.h#L579
     *      invoked by
     *      + https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/iked.h#L580
     *       + https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/policy.c#L416
     *        + https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/ikev2.c#L1158
     *         + https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/ikev2.c#L381
     */

    ikev2_dispatch_cert(-1, NULL, &imsg);

    destroy_iked_env_aux(env);
    destroy_iked_env(env);
    iked_env = NULL;

    return 0;
}
