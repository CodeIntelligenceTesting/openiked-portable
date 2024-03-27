#include <pthread.h>
#include <unistd.h>

#include <assert.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "ikectl_fuzzer_impl.hpp"

void blockSignals()
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGPIPE);
    sigaddset(&set, SIGUSR1);
    
    int retval = pthread_sigmask(SIG_BLOCK, &set, NULL);
    assert(retval == 0);
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    /*
     * block signals here rather then when spawning the thread, as libFuzz might
     * unblock them. See
     *   https://github.com/llvm/llvm-project/blob/3ada883f7c96e099e1a665c091751bff5f16690e/compiler-rt/lib/fuzzer/FuzzerDriver.cpp#L840
     */
    blockSignals();
    printf("%s:%d: Fuzzer is now blocking signals.\n", __FILE__, __LINE__);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t nmemb)
{
    return 0;
}
