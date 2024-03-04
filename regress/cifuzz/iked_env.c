#include <err.h>
#include <pwd.h>
#include <syslog.h>
#include <unistd.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <event.h>

#include "ca.h"
#include "iked.h"
#include "iked_env.h"
#include "vroute_cleanup_leaked_sockets.h"

int
parent_configure(struct iked *env)
{
	struct sockaddr_storage	 ss;

	if (parse_config(env->sc_conffile, env) == -1) {
		proc_kill(&env->sc_ps);
		exit(1);
	}

	if (env->sc_opts & IKED_OPT_NOACTION) {
		fprintf(stderr, "configuration OK\n");
		proc_kill(&env->sc_ps);
		exit(0);
	}

	env->sc_pfkey = -1;
	config_setpfkey(env);

	/* Send private and public keys to cert after forking the children */
	if (config_setkeys(env) == -1)
		fatalx("%s: failed to send keys", __func__);
	config_setreset(env, RESET_CA, PROC_CERT);

	/* Now compile the policies and calculate skip steps */
	config_setcompile(env, PROC_IKEV2);

	bzero(&ss, sizeof(ss));
	ss.ss_family = AF_INET;

#ifdef __APPLE__
	int nattport = env->sc_nattport;
	sysctlbyname("net.inet.ipsec.esp_port", NULL, NULL, &nattport, sizeof(nattport));
#endif

	/* see comment on config_setsocket() */
	if (env->sc_nattmode != NATT_FORCE)
		config_setsocket(env, &ss, htons(IKED_IKE_PORT), PROC_IKEV2, 0);
	if (env->sc_nattmode != NATT_DISABLE)
		config_setsocket(env, &ss, htons(env->sc_nattport), PROC_IKEV2, 1);

	bzero(&ss, sizeof(ss));
	ss.ss_family = AF_INET6;

	if (env->sc_nattmode != NATT_FORCE)
		config_setsocket(env, &ss, htons(IKED_IKE_PORT), PROC_IKEV2, 0);
	if (env->sc_nattmode != NATT_DISABLE)
		config_setsocket(env, &ss, htons(env->sc_nattport), PROC_IKEV2, 1);

	/*
	 * pledge in the parent process:
	 * It has to run fairly late to allow forking the processes and
	 * opening the PFKEY socket and the listening UDP sockets (once)
	 * that need the bypass ioctls that are never allowed by pledge.
	 *
	 * Other flags:
	 * stdio - for malloc and basic I/O including events.
	 * rpath - for reload to open and read the configuration files.
	 * proc - run kill to terminate its children safely.
	 * dns - for reload and ocsp connect.
	 * inet - for ocsp connect.
	 * route - for using interfaces in iked.conf (SIOCGIFGMEMB)
	 * wroute - for adding and removing addresses (SIOCAIFGMEMB)
	 * sendfd - for ocsp sockets.
	 */
	if (pledge("stdio rpath proc dns inet route wroute sendfd", NULL) == -1)
		fatal("pledge");

	config_setstatic(env);
	config_setcoupled(env, env->sc_decoupled ? 0 : 1);
	config_setocsp(env);
	config_setcertpartialchain(env);
	/* Must be last */
	config_setmode(env, env->sc_passive ? 1 : 0);

	return (0);
}

struct iked *create_iked_env()
{
    struct iked *env = malloc(sizeof(struct iked));
    memset(env, 0, sizeof(*env));

    /*
     * second parameter is not used if first one evaluates to true
     */
    log_init(1, LOG_DEBUG);

    env->sc_opts = 0;
    env->sc_nattmode = NATT_DEFAULT;
    env->sc_nattport = IKED_NATT_PORT;

    struct privsep *ps = &env->sc_ps;
    ps->ps_env = env;
    TAILQ_INIT(&ps->ps_rcsocks);

    if (strlcpy(env->sc_conffile, IKED_CONFIG, PATH_MAX) >= PATH_MAX)
	errx(1, "config file exceeds PATH_MAX");

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
    ps->ps_csock.cs_name = IKED_SOCKET;
    
    /* again, LOG_DAEMON not readt as long as first parameter is true */
    log_init(1, LOG_DAEMON);
    log_setverbose(1);

    ps->ps_noaction = 1;
    ps->ps_instance = 0;

    /*
     * skip all libevent invokations and signal setup
     */
#if 0
    /* only the parent returns */
    proc_init(ps, procs, nitems(procs), debug, argc0, argv, proc_id);

    setproctitle("parent");
    log_procinit("parent");

    event_init();

    signal_set(&ps->ps_evsigint, SIGINT, parent_sig_handler, ps);
    signal_set(&ps->ps_evsigterm, SIGTERM, parent_sig_handler, ps);
    signal_set(&ps->ps_evsigchld, SIGCHLD, parent_sig_handler, ps);
    signal_set(&ps->ps_evsighup, SIGHUP, parent_sig_handler, ps);
    signal_set(&ps->ps_evsigpipe, SIGPIPE, parent_sig_handler, ps);
    signal_set(&ps->ps_evsigusr1, SIGUSR1, parent_sig_handler, ps);

    signal_add(&ps->ps_evsigint, NULL);
    signal_add(&ps->ps_evsigterm, NULL);
    signal_add(&ps->ps_evsigchld, NULL);
    signal_add(&ps->ps_evsighup, NULL);
    signal_add(&ps->ps_evsigpipe, NULL);
    signal_add(&ps->ps_evsigusr1, NULL);

    proc_connect(ps);
#endif

#if defined(HAVE_VROUTE)
    vroute_init(env);
#endif

    strcpy(env->sc_conffile, "iked.conf");
    /*
     * might have to stub parent_configure
     */
    /*
     * Need to drop non-owner read bits
     * https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/parse.y#L1713
     */
    int mode = chmod(env->sc_conffile, S_IRUSR);
    assert(mode == 0);



    if (parent_configure(env) == -1)
        fatalx("configuration failed");
#if 0
    event_dispatch();
#endif

    return env;
}

/*
 * additional initializers not within main of iked.c
 */
void create_iked_env_aux(struct iked *env)
{
    ca_init(env);
}

void destroy_iked_env_aux(struct iked *env)
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

void destroy_iked_env(struct iked *env)
{
    // proc_kill(&env->sc_ps);

#if defined(HAVE_VROUTE)
	vroute_cleanup(env);
	vroute_cleanup_leaked_sockets(env);
#endif
	free(env->sc_vroute);
	free(env);
}
