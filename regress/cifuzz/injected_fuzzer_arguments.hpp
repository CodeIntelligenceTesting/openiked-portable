#pragma once

extern "C" void injected_fuzzer_send_arguments();
extern "C" void injected_fuzzer_read_arguments(int *argsc, char **argsv);