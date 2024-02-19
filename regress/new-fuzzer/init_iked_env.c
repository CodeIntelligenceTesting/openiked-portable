#include <pwd.h>
#include <unistd.h>

#include <stddef.h>
#include <string.h>

#include <event.h>

#include "fuzzdataprovider.h"
#include "iked.h"

struct iked *create_iked_env()
{
    /*
     * From https://github.com/openiked/openiked-portable/blob/6a36fe8f216aea8a2255b9a8b98a5b53a75eb60a/iked/iked.c#L194
     */
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
    /*
     * From https://github.com/openiked/openiked-portable/blob/6a36fe8f216aea8a2255b9a8b98a5b53a75eb60a/iked/iked.c#L543
     * but do not invoke exit()
     */

    // proc_kill(&env->sc_ps);

#if defined(HAVE_VROUTE)
	vroute_cleanup(env);
#endif
	free(env->sc_vroute);
	free(env);
}

int LLVMFuzzerTestOneInput(const uint8_t *__data, size_t __size)
{
    FuzzDataProvider provider = FuzzDataConstruct(__data, __size);

    /* need to set global variable */
    struct iked *env = create_iked_env();
    iked_env = env;

    typedef struct {
        struct sockaddr addr;
        struct sockaddr mask;
        unsigned int ifidx;
    } vroute_getaddr_data_t;

    vroute_getaddr_data_t vroute_getaddr_data = {
        .addr = FuzzDataReadSockAddr(&provider),
        .mask = FuzzDataReadSockAddr(&provider),
        .ifidx = FuzzDataReadUint32(&provider)
    };

    struct imsg imsg = {
        .hdr = {
            .type = FuzzDataReadUint32(&provider),
	        .len = sizeof(struct imsg_hdr) + /* sizeof(int) */ + sizeof(vroute_getaddr_data_t),
            .flags = FuzzDataReadUint16(&provider),
            .peerid = FuzzDataReadUint32(&provider),
            .pid = FuzzDataReadUint32(&provider)
        },
        .fd = -1,
        .data = &vroute_getaddr_data
    };
    vroute_getaddr(env, &imsg);

    destroy_iked_env(env);
    iked_env = NULL;

    return 0;
}
