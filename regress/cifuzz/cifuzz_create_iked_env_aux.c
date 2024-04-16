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

/*
 * additional initializers not within main of iked.c
 */
void cifuzz_create_iked_env_aux(struct iked *env)
{
    ca_init(env);
}
