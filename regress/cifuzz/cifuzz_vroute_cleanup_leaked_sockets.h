#pragma once

#include "iked.h"

/**
 * Fix socket descriptor leak.
 * TODO: Get this into upstream
 **/
    
/**
 * At this point we are not aware of whether we're using vroute or vroute-netlink.
 *
 * CMake has this information, so have it compile different implementation
 * source files depending on whether we're netlink or not.
 **/
void cifuzz_vroute_cleanup_leaked_sockets(struct iked *env);
