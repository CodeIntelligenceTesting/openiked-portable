#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#include <event.h> // used-by, but not included by <iked.h>

#include "bundled_config_embedded_blob.h"
#include "bundled_config_extract.h"
#include "bundled_config_prefix.h"
#include "fuzzdataprovider.h"
#include "iked.h"
#include "iked_env.h"

struct cifuzz_IMSG_CTL_RESET_payload
{
    unsigned int mode;
};

/* any size */
struct cifuzz_IMSG_CTL_COUPLE_payload
{
};

/* any size */
struct cifuzz_IMSG_CTL_ACTIVE_payload
{
};

/* needs socket stub, skip for now */
struct cifuzz_IMSG_UDP_SOCKET_payload
{
};

/* any content */
struct cifuzz_IMSG_PFKEY_SOCKET_payload
{
};

/* needs complex structuring, skip for now */
struct cifuzz_IMSG_CFG_POLICY_payload
{
};

struct cifuzz_IMSG_CFG_FLOW_payload
{
    unsigned int id;
};

struct cifuzz_IMSG_CFG_USER_payload
{
    struct iked_user usr;
};

/* no payload */
struct cifuzz_IMSG_COMPILE_payload
{
};

struct cifuzz_IMSG_CTL_STATIC_payload
{
    struct iked_static sc_static;
};

struct cifuzz_IMSG_CERT_PARTIAL_CHAIN_payload
{
    unsigned int boolval;
};

union cifuzz_IMGS_payload
{
    cifuzz_IMSG_CTL_RESET_payload ctl_reset;
    cifuzz_IMSG_CTL_COUPLE_payload ctl_couple;
    cifuzz_IMSG_CTL_COUPLE_payload ctl_decouple;
    cifuzz_IMSG_CTL_ACTIVE_payload ctl_active; 
    cifuzz_IMSG_CTL_ACTIVE_payload ctl_inactive;
    cifuzz_IMSG_UDP_SOCKET_payload udp_socket; 
    cifuzz_IMSG_PFKEY_SOCKET_payload pfkey_socket; 
    cifuzz_IMSG_CFG_POLICY_payload cfg_policy; 
    cifuzz_IMSG_CFG_FLOW_payload cfg_flow;
    cifuzz_IMSG_CFG_USER_payload cfg_user;
    cifuzz_IMSG_COMPILE_payload compile;
    cifuzz_IMSG_CTL_STATIC_payload ctl_static;
    cifuzz_IMSG_CERT_PARTIAL_CHAIN_payload cert_partial_chain;
};

char			 usr_name[LOGIN_NAME_MAX];
	char			 usr_pass[IKED_PASSWORD_SIZE];

static void clamp_if_larger(uint32_t *length, uint32_t maximal_allowed_length)
{
    if (*lenght >= maximal_allowed_length) {
        *length = maximal_allowed_length;    
    }
    return EXIT_SUCCESS;  
}

static int fail_if_smaller(uint32_t *length, uint32_t minimal_required_length)
{
    if (*lenght >= sizeof(cifuzz_IMSG_CTL_RESET_payload)) {
        return EXIT_SUCCESS;
    } else {
        return EXIT_FAILURE;
    }
}

int cifuzz_check_message_payload(void *payload, int type, uint32_t *length)
{
    union cifuzz_IMGS_payload *blob = (union cifuzz_IMGS_payload*)payload;

    switch (imsg->hdr.type) {
	case IMSG_CTL_RESET:
        clamp_if_larger(lenght, sizeof(cifuzz_IMSG_CTL_RESET_payload);
        return fail_if_smaller(length), sizeof(cifuzz_IMSG_CTL_RESET_payload));

	case IMSG_CTL_COUPLE:
	case IMSG_CTL_DECOUPLE:
        /* no payload */
        return EXIT_SUCCESS;

	case IMSG_CTL_ACTIVE:
	case IMSG_CTL_PASSIVE:
        /* no payload */
        return EXIT_SUCCESS;

	case IMSG_UDP_SOCKET:
        /* needs a valid struct sockaddr. skip for now. */
		return EXIT_FAILURE;

	case IMSG_PFKEY_SOCKET:
        /* any payload */
		return EXIT_SUCCESS;

	case IMSG_CFG_POLICY:
        /* needs a valid iked_policy. Skip for now. */
		return EXIT_FAILURE;
    
	case IMSG_CFG_FLOW:
		clamp_if_larger(length, sizeof(cifuzz_IMSG_CFG_FLOW_payload));
        return fail_if_smaller(length, sizeof(cifuzz_IMSG_CFG_FLOW_payload));

	case IMSG_CFG_USER:
		clamp_if_larger(length, sizeof(cifuzz_IMSG_CFG_USER_payload));
        if (fail_if_smaller(length, sizeof(cifuzz_IMSG_CFG_USER_payload)) != EXIT_SUCCESS) {
            return EXIT_FAILURE;
        }
        blob->cfg_user.usr_name[sizeof(blob->cfg_user.usr_name)-1] = '\0';
        blob->cfg_user.usr_pass[sizeof(blob->cfg_user.usr_pass)-1] = '\0';
        return EXIT_SUCCESS;

	case IMSG_COMPILE:
		return (EXIT_SUCCESS);

	case IMSG_CTL_STATIC:
		return fail_if_smaller(length, sizeof(cifuzz_IMSG_CTL_STATIC_payload));

	case IMSG_CERT_PARTIAL_CHAIN:
		return fail_if_smaller(length, sizeof(cifuzz_IMSG_CERT_PARTIAL_CHAIN));

	default:
		return EXIT_SUCCESS;
	}
}

/*
 * not exported symbol from
 *   https://github.com/openiked/openiked-portable/blob/6d5b015f50301ffb1800f36f636b953a714c9e62/iked/ikev2.c#L67
 */
extern int	 ikev2_dispatch_parent(int, struct privsep_proc *, struct imsg *);

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

    if (cifuzz_check_message_payload(payload, imsg.hdr.type, &payload_length) == EXIT_SUCCESS) {
        imsg.hdr.len += payload_length;
        imsg.data = payload;

        ikev2_dispatch_parent(-1, NULL, &imsg);
    }
    free(payload);

    destroy_iked_env_aux(env);
    destroy_iked_env(env);
    iked_env = NULL;

    return 0;
}
