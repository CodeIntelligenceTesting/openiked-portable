#include <pthread.h>
#include <unistd.h>

#include <assert.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

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

    int argsc = 2;
    char **argsv = (char **)calloc(sizeof(char *), argsc+1);
    argsv[0] = "fuzzer";
    argsv[1] = "-runs=1";
    argsv[2] = NULL;
    LLVMFuzzerRunDriver(&argsc, &argsv, &LLVMFuzzerTestOneInput);
    free(argsv);

    return NULL;
}

void setup()
{
    pthread_t fuzzer_thread;
    printf("%s:%d: Spawning fuzzer thread...\n", __FILE__, __LINE__);
    int created = pthread_create(&fuzzer_thread, NULL, &fuzzerThreadMain, NULL);
    assert(created == 0);
    int detached = pthread_detach(fuzzer_thread);
    assert(detached == 0);
}

void cleanup()
{
    printf("%s:%d: cleanup.\n", __FILE__, __LINE__);
}
