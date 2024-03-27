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
static pthread_t g_fuzzer_thread;

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
    printf("%s:%d: Spawning fuzzer thread...\n", __FILE__, __LINE__);
    int created = pthread_create(&g_fuzzer_thread, NULL, &fuzzerThreadMain, NULL);
    assert(created == 0);
    int detached = pthread_detach(g_fuzzer_thread);
    assert(detached == 0);
}

void cleanup()
{
    printf("%s:%d: cleanup.\n", __FILE__, __LINE__);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    /*
     * block signals here rather then when spawning the thread, as libFuzz might
     * unblock them. See
     *   https://github.com/llvm/llvm-project/blob/3ada883f7c96e099e1a665c091751bff5f16690e/compiler-rt/lib/fuzzer/FuzzerDriver.cpp#L840
     */
    blockSignals();
    printf("%s:%d: Fuzzer thread now blocking signals.\n", __FILE__, __LINE__);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t nmemb)
{
    return 0;
}
