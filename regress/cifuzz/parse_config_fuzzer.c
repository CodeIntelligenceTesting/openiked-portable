#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>

#include <event.h> // used-by, but not included by <iked.h>

#include "fuzzdataprovider.h"
#include "iked.h"
#include "cifuzz_iked_env.h"
#include "mocks/mocks.h"

int LLVMFuzzerTestOneInput(const uint8_t *__data, size_t __size)
{
    FuzzDataProvider provider = FuzzDataConstruct(__data, __size);

    /* need to set global variable */
    struct iked *env = cifuzz_create_iked_env();
    iked_env = env;
    cifuzz_create_iked_env_aux(env);

#if 0 /* asan panics in mktemp? */
    char *filename = mktemp("iked.conf.XXXXXX");
    assert(filename != NULL);
#else
    char filename[32];
    sprintf(filename, "iked.conf.%d", (int)getpid());
#endif

    FILE *f = fopen(filename, "w+");
    if (f == NULL) {
         /*
          * multiprocess fuzzing?
          */
         return -1;
    }

    ssize_t written = fwrite(__data, 1, __size, f);
    assert(written == __size);
    fclose(f);

    /*
     * Need to drop non-owner read bits
     * https://github.com/CodeIntelligenceOSSOnboardings/openiked-portable/blob/515db3ea9c50a641689c79e5972ff5900abe0496/iked/parse.y#L1715
     */
    int mode = chmod(filename, S_IRUSR);
    assert(mode == 0);

    parse_config(filename, env);

    int removed = remove(filename);
    assert(removed == 0);

    cifuzz_destroy_iked_env_aux(env);
    cifuzz_destroy_iked_env(env);
    event_base_free(NULL);
    iked_env = NULL;

    return 0;
}
