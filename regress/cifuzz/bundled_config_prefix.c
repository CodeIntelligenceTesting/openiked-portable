#include "bundled_config_extract.h"

static const char __cifuzz_bundled_config_prefix[] = #CMAKE_INSTALL_SYSCONFDIR ;

const char *cifuzz_bundled_config_prefix()
{
    return __cifuzz_bundled_config_prefix;
}