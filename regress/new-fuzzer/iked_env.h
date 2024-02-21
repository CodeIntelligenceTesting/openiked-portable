#pragma once

#include "iked.h"

/*
 * Allocate an iked structure as is done in https://github.com/openiked/openiked-portable/blob/6a36fe8f216aea8a2255b9a8b98a5b53a75eb60a/iked/iked.c#L194
 * but skip super user assertions, libevent setup and posix signal handler setup that requires procedures local to iked.c
 *
 * The allocated iked structure needs to be released via `destroy_iked_env`.
 */
struct iked *create_iked_env();

/*
 * Release an iked structure as is done in https://github.com/openiked/openiked-portable/blob/6a36fe8f216aea8a2255b9a8b98a5b53a75eb60a/iked/iked.c#L543
 * but do not invoke exit()
 */
void destroy_iked_env(struct iked *env);
