#include <pthread.h>
#include <unistd.h>

#include <assert.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern int main(int argsc, char **argsv);
extern int LLVMFuzzerRunDriver(int *argc, char ***argv,
                  int (*UserCb)(const uint8_t *Data, size_t Size));

static void setup() __attribute__ ((constructor));
static void cleanup() __attribute__ ((destructor));
static pthread_t g_fuzzer_thread;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
}

void LLVMFuzzerTestOneInput(size_t nmemb, uint8_t *data)
{
}

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

void fuzzerThreadMain(void)
{
    printf("%s:%d: Fuzzer thread spawned.\n", __FILE__, __LINE__);

    blockSignals();
    printf("%s:%d: Fuzzer thread now blocking signals.\n", __FILE__, __LINE__);
}

void setup()
{
    printf("%s:%d: Spawning fuzzer thread...\n", __FILE__, __LINE__);
    int created = pthread_create(&g_fuzzer_thread, NULL, &fuzzerThreadMain, NULL);
    assert(created == 0);
}

void cleanup()
{
    void *junk;
    pthread_join(&g_fuzzer_thread, &junk);
    printf("%s:%d: Joined with fuzzer thread.\n", __FILE__, __LINE__);
}