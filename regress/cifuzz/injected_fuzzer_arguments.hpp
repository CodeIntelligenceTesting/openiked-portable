#pragma once

extern "C" void injected_fuzzer_send_arguments();
extern "C" void injected_fuzzer_recv_arguments(int *argsc, char **argsv);