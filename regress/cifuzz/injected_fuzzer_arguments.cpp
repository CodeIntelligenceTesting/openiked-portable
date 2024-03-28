#include <unistd.h>

#include <cstdlib>

#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <nlohmann/json.hpp>

#include "injected_fuzzer_arguments.h"

static void populate_args_from_json(const nlohmann::json &args, int *_argsc, char ***_argsv)
{
    int    argsc = args.size();
    char **argsv = new char* [argsc+1];
    for(int i=0; i<args.size(); ++i) {
        std::string arg = args.at(i);
        argsv[i] = new char[arg.size() + 1];
        strcpy(argsv[i], arg.c_str());
    }
    argsv[argsc] = nullptr;

    *_argsc = argsc;
    *_argsv = argsv;
}

static nlohmann::json read_from_environment(const char *varname)
{
    char *envvar(getenv(varname));
    assert(envvar != nullptr);

    std::stringstream in;
    in << envvar;

    nlohmann::json json;
    in >> json;

    return json;
}

int injected_fuzzer_arguments_available()
{
    if (getenv("CIFUZZ_INJECTED_FUZZER_ARGUMENTS") != nullptr) {
        int want_pid = read_from_environment("CIFUZZ_INJECTED_FUZZER_ARGUMENTS").at("pid");
        if (want_pid == getpid()) {
            return 1;
        } else {
            printf("%s:%d: Rejecting CIFUZZ_INJECTED_FUZZER_ARGUMENTS present on %d but payload is for %d\n", __FILE__, __LINE__, (int)getpid(), want_pid);
        }
    }
    return 0;
}

void injected_fuzzer_recv_arguments(int *_argsc, char ***_argsv)
{
    nlohmann::json args(read_from_environment("CIFUZZ_INJECTED_FUZZER_ARGUMENTS"));
    populate_args_from_json(args.at("libfuzzer"), _argsc, _argsv);
    /*
     * unset the environment variable to prevent it from getting inherited
     */
    int unsetenv_retval(unsetenv("CIFUZZ_INJECTED_FUZZER_ARGUMENTS"));
    assert(unsetenv_retval == 0);
}

void injected_fuzzer_main_arguments(int *_argsc, char ***_argsv)
{
    nlohmann::json args(read_from_environment("CIFUZZ_INJECTED_FUZZER_ARGUMENTS"));
    populate_args_from_json(args.at("main"), _argsc, _argsv);
}

void injected_fuzzer_send_arguments(int argsc, char **argsv)
{
    std::string arg0(argsv[1]);

    nlohmann::json dump = nlohmann::json::object();
    dump["pid"] = (int)getpid();
    dump["main"] = nlohmann::json::array({arg0});
    dump["libfuzzer"] = nlohmann::json::array({arg0});

    bool seen_dash_dash(false);
    for (int i=2; i<argsc; ++i) {
        std::string argi(argsv[i]);
        if (!seen_dash_dash) {
            if (argi.compare("--") == 0) {
                seen_dash_dash = true;
                continue;
            }
        }
        
        if(seen_dash_dash) {
            dump["main"].push_back(argi);
        } else {
            dump["libfuzzer"].push_back(argi);
        }
    }
    std::stringstream sstream;
    sstream << std::setw(2) << dump << '\n';

    int setenv_retval = setenv("CIFUZZ_INJECTED_FUZZER_ARGUMENTS", sstream.str().c_str(), 0);
    assert(setenv_retval == 0);

    printf("%s:%d: CIFUZZ_INJECTED_FUZZER_ARGUMENTS=%s\n", __FILE__, __LINE__, sstream.str().c_str());
}

void injected_fuzzer_free_arguments(int *_argsc, char ***_argsv)
{
    char **argsv = *_argsv;
    for(int i=0; i<*_argsc; ++i)
    {
        delete [] argsv[i];
    }
}