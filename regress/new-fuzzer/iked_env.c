#include <pwd.h>
#include <unistd.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <event.h>

#include "iked.h"
#include "iked_env.h"

struct iked *create_iked_env()
{
    struct iked *env = malloc(sizeof(struct iked));
    memset(env, 0, sizeof(*env));

    /*
     * second parameter is not used if first one evaluates to true
     */
    log_init(1, -1);

    env->sc_opts = 0;
    env->sc_nattmode = NATT_DEFAULT;
    env->sc_nattport = IKED_NATT_PORT;

    struct privsep *ps = &env->sc_ps;
    ps->ps_env = env;
    TAILQ_INIT(&ps->ps_rcsocks);

    ca_sslinit();
    group_init();
    policy_init(env);

#if 0
    /*
     * really need?
     */
    if (geteuid())
		errx(1, "need root privileges");
#endif

    ps->ps_pw = getpwnam(IKED_USER);
#if 0
    /*
     * not fatal
     */
    if (ps->ps_pw == NULL)
		errx(1, "unknown user %s", IKED_USER);
#endif

    log_setverbose(1);

    // ps->ps_noaction = 1;
    ps->ps_instance = 0;

#if defined(HAVE_VROUTE)
    vroute_init(env);
#endif

    return env;
}

void destroy_iked_env(struct iked *env)
{
    // proc_kill(&env->sc_ps);

#if defined(HAVE_VROUTE)
	vroute_cleanup(env);
#endif
	free(env->sc_vroute);
	free(env);
}