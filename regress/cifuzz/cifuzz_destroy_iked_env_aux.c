#include <err.h>
#include <pwd.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <event.h>

#include "ca.h"
#include "iked.h"
#include "cifuzz_iked_env.h"

void cifuzz_destroy_iked_env_aux(struct iked *env)
{
#if 0 /* released in ca_shutdown */
    /*
     * allocated in
     *   https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/ikev2.c#L342
     * and not neccessarily freed.
     */
    ibuf_free(env->sc_certreq);
    env->sc_certreq = NULL;
#endif

    /*
     * allocated in create_iked_env_aux
     */
    ca_shutdown(); /* env passed via global variable */
}
