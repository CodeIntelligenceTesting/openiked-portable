#pragma once

#include <stdint.h>

#include <event.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

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
 * Initialize a ca_store in env->sc_priv, as is done by `ca_run` in
 *
 *   https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/ca.c#L118
 *
 * `ca_shutdown` from ca.c can be used to release resources associated with the ca
 *
 * Do not re-initialize a ca within `env` w/o prior `ca_shutdown` call.
 */
void ca_init(struct iked *env);

/*
 * defined in
 * https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/ca.c
 * but doesn't export a prototype
 */
void	 ca_run(struct privsep *, struct privsep_proc *, void *);
void	 ca_shutdown(void);
void	 ca_reset(struct privsep *);
int	 ca_reload(struct iked *);

int	 ca_cert_local(struct iked *, X509 *);
int	 ca_getreq(struct iked *, struct imsg *);
int	 ca_getcert(struct iked *, struct imsg *);
int	 ca_getauth(struct iked *, struct imsg *);
X509	*ca_by_subjectpubkey(X509_STORE *, uint8_t *, size_t);
X509	*ca_by_issuer(X509_STORE *, X509_NAME *, struct iked_static_id *);
X509	*ca_by_subjectaltname(X509_STORE *, struct iked_static_id *);
void	 ca_store_certs_info(const char *, X509_STORE *);
int	 ca_subjectpubkey_digest(X509 *, uint8_t *, unsigned int *);
int	 ca_x509_subject_cmp(X509 *, struct iked_static_id *);
int	 ca_validate_pubkey(struct iked *, struct iked_static_id *,
	    void *, size_t, struct iked_id *);
int	 ca_validate_cert(struct iked *, struct iked_static_id *,
	    void *, size_t, STACK_OF(X509) *, X509 **);
EVP_PKEY *
	 ca_bytes_to_pkey(uint8_t *, size_t);
int	 ca_privkey_to_method(struct iked_id *);
struct ibuf *
	 ca_x509_serialize(X509 *);
int	 ca_x509_subjectaltname_do(X509 *, int, const char *,
	    struct iked_static_id *, struct iked_id *);
int	 ca_x509_subjectaltname_cmp(X509 *, struct iked_static_id *);
int	 ca_x509_subjectaltname_log(X509 *, const char *);
int	 ca_x509_subjectaltname_get(X509 *cert, struct iked_id *);
int	 ca_dispatch_parent(int, struct privsep_proc *, struct imsg *);
int	 ca_dispatch_ikev2(int, struct privsep_proc *, struct imsg *);
int	 ca_dispatch_control(int, struct privsep_proc *, struct imsg *);
void	 ca_store_info(struct iked *, const char *, X509_STORE *);