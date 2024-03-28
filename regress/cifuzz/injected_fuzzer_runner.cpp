#include <stdio.h>
#include <unistd.h>

#include "injected_fuzzer_arguments.hpp"

int main(int argsc, char **argsv)
{
    injected_fuzzer_send_arguments(argsc, argsv);
    return exec(argsv[1], &argsv[1]);
}