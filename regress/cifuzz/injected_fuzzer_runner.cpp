#include <stdio.h>
#include <unistd.h>

#include "injected_fuzzer_arguments.hpp"

static int usage(const char *args0)
{
    printf(
      "%s:%d: SYNTAX: %s fuzzer-path arg1 [arg2 [arg3 [...]]] [--] [marg1 [marg2 [...]]]\n"
      "Invocation of injected fuzztarget target-path\n"
      "Arguments passed before -- are passed to libfuzzer, \n"
      "while arguments passed after -- are passed to the main function",
      __FILE__,
      __LINE__,
      args0
    );
    return 1;
}

static int run_fuzzer()
{
    int argsc;
    char **argsv;

    injected_fuzzer_main_arguments(&argsc, &argsv);
    fflush(stdout);
    fflush(stderr);
    return execv(argsv[0], argsv);
}

int main(int argsc, char **argsv)
{
    if (argsc < 2) {
        return usage(argsv[0]);
    }
    injected_fuzzer_send_arguments(argsc, argsv);
    return run_fuzzer();
}