#pragma once

#include <stdint.h>

#include <event.h>

#include "iked.h"

/*
 * copy-pasted from 
 * https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/ca.c#L98
 */

struct ca_store {
	X509_STORE	*ca_cas;
	X509_LOOKUP	*ca_calookup;

	X509_STORE	*ca_certs;
	X509_LOOKUP	*ca_certlookup;

	struct iked_id	 ca_privkey;
	struct iked_id	 ca_pubkey;

	uint8_t		 ca_privkey_method;
};

/*
 * Initialize a ca_store in env->sc_priv, as is done by
 * https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/ca.c#L118
 *
 * `ca_shutdown` from ca.c can be used to release resources associated with the ca
 *
 * Do not re-initialize a ca within `env` w/o prior `ca_shutdown` call.
 */
void ca_init(struct iked *env);

/*
 * defined in
 * https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/ca.c#L145
 * but doesn't export a prototype
 */
void ca_shutdown(void);