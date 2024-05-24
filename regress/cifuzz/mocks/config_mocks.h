#ifndef CONFIG_MOCKS_H
#define CONFIG_MOCKS_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>
#include "iked.h"
#include "ikev2.h"

/*
This function is called by configure parent, after spawning the ca process. If
it fails, iked exits. To simulate this in the fuzzing environment we are gonna
call it as part of the env setup. The difference is that we are NOT going to use
events to set up the env structure, like the original function does.
*/
int __wrap_config_setkeys(struct iked *env) {
#ifdef DEBUG
    printf("Called mocked config_setkeys.");
#endif

    FILE *fp = NULL;
    EVP_PKEY *key = NULL;
    struct iked_id privkey;
    struct iked_id pubkey;
    struct iovec iov[2];
    int ret = -1;

    struct iked_id privkey_copy;
    struct iked_id pubkey_copy;
    memset(&privkey, 0, sizeof(privkey));
    memset(&pubkey, 0, sizeof(pubkey));
    memset(&privkey_copy, 0, sizeof(privkey_copy));
    memset(&pubkey_copy, 0, sizeof(pubkey_copy));

    if ((fp = fopen(IKED_PRIVKEY, "r")) == NULL) {
        log_warn("%s: failed to open private key", __func__);
        goto done;
    }

    if ((key = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL) {
        log_warnx("%s: failed to read private key", __func__);
        goto done;
    }

    if (ca_privkey_serialize(key, &privkey) != 0) {
        log_warnx("%s: failed to serialize private key", __func__);
        goto done;
    }
    if (ca_pubkey_serialize(key, &pubkey) != 0) {
        log_warnx("%s: failed to serialize public key", __func__);
        goto done;
    }

    // Make copies for private and public keys,
    // these will be passed to ca_getkey
    // we could directly pass ca_pubkey/ca_privkey
    // but kept the copies for better debugging
    if (ca_privkey_serialize(key, &privkey_copy) != 0) {
        log_warnx("%s: failed to serialize private key copy", __func__);
        goto done;
    }
    if (ca_pubkey_serialize(key, &pubkey_copy) != 0) {
        log_warnx("%s: failed to serialize public key copy", __func__);
        goto done;
    }

    ca_getkey(NULL, &privkey_copy, IMSG_PRIVKEY);
    ca_getkey(NULL, &pubkey_copy, IMSG_PUBKEY);

    /*
    The code bellow composes an event to write the keys
    via another process.
    We written the keys into env via the ca_getkey function
    to simplify the setup.
    */

    /*
    iov[0].iov_base = &privkey;
    iov[0].iov_len = sizeof(privkey);
    iov[1].iov_base = ibuf_data(privkey.id_buf);
    iov[1].iov_len = ibuf_size(privkey.id_buf);

    if (proc_composev(&env->sc_ps, PROC_CERT, IMSG_PRIVKEY, iov, 2) == -1) {
            log_warnx("%s: failed to send private key", __func__);
            goto done;
    }

    iov[0].iov_base = &pubkey;
    iov[0].iov_len = sizeof(pubkey);
    iov[1].iov_base = ibuf_data(pubkey.id_buf);
    iov[1].iov_len = ibuf_size(pubkey.id_buf);

    if (proc_composev(&env->sc_ps, PROC_CERT, IMSG_PUBKEY, iov, 2) == -1) {
            log_warnx("%s: failed to send public key", __func__);
            goto done;
    }

    */
    ret = 0;
done:
    if (fp != NULL)
        fclose(fp);

    ibuf_free(pubkey.id_buf);
    ibuf_free(privkey.id_buf);
    EVP_PKEY_free(key);

    return (ret);
}

#endif // CONFIG_MOCKS_H