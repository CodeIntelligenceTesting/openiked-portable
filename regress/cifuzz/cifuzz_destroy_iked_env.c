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

#include "iked.h"
#include "cifuzz_iked_env.h"
#include "cifuzz_vroute_cleanup_leaked_sockets.h"

void cifuzz_destroy_iked_env(struct iked *env)
{
    // proc_kill(&env->sc_ps);

#if defined(HAVE_VROUTE)
	vroute_cleanup(env);
	cifuzz_vroute_cleanup_leaked_sockets(env);
#endif
	free(env->sc_vroute);
	free(env);
}
