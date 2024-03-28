#include <pthread.h>
#include <unistd.h>

#include <assert.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "injected_fuzzer_arguments.hpp"

extern int main(int argsc, char **argsv);
extern int LLVMFuzzerRunDriver(int *argc, char ***argv,
                  int (*UserCb)(const uint8_t *Data, size_t Size));

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t nmemb);

static void setup() __attribute__ ((constructor));
static void cleanup() __attribute__ ((destructor));

void *fuzzerThreadMain(void *)
{
    printf("%s:%d: Fuzzer thread spawned.\n", __FILE__, __LINE__);

    int argsc;
    char **argsv;
    injected_fuzzer_recv_arguments(&argsc, &argsv);
    LLVMFuzzerRunDriver(&argsc, &argsv, &LLVMFuzzerTestOneInput);
    injected_fuzzer_free_arguments(&argsc, &argsv);

    return NULL;
}

void setup()
{
    if (injected_fuzzer_arguments_available()) {
        pthread_t fuzzer_thread;
        printf("%s:%d: Spawning fuzzer thread on %d...\n", __FILE__, __LINE__, (int)getpid());
        int created = pthread_create(&fuzzer_thread, NULL, &fuzzerThreadMain, NULL);
        assert(created == 0);
        int detached = pthread_detach(fuzzer_thread);
        assert(detached == 0);
    } else {
        printf("%s:%d: No arguments available to %d, not spawning fuzzer thread.\n", __FILE__, __LINE__, (int)getpid());
    }
}

void cleanup()
{
    printf("%s:%d: cleanup.\n", __FILE__, __LINE__);
}
