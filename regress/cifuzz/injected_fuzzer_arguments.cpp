#include <cstdlib>

#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <nlohmann/json.hpp>

#include "injected_fuzzer_arguments.hpp"

static void populate_args_from_json(const nlohmann::json::array &args, int *_argsc, char ***_argsv)
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

void injected_fuzzer_recv_arguments(int *_argsc, char ***_argsv)
{
    std::fstream in("dump.json", std::fstream::in);

    nlohmann::json args;
    in >> args;

    populate_args_from_json(args.at("libfuzzer"), _argsc, _argsv);
}

int injected_fuzzer_send_arguments(int argsc, char **argsv)
{
    std::string arg0(argsv[1]);

    nloahman::json dump = nlohmann::json::object();
    dump["main"] = nlohmann::json::array({arg0});
    dump["libfuzzer"] = nlohmann::json::array({arg0});

    bool seen_dash_dash(false);
    for (int i=2; i<argsc; ++i) {
        std::string argi(argsv[i]);
        if (!seen_dash_dash) {
            if (argi.compare("==") == 0) {
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

    std::fstream out("dump.json", std::fstream::out | std::fstream::trunc);
    // serialize JSON
    out << std::setw(2) << args << '\n';

    return main_args_index;
}

void injected_fuzzer_free_arguments(int *_argsc, char ***_argsv)
{
    char **argsv = *_argsv;
    for(int i=0; i<*_argsc; ++i)
    {
        delete [] argsv[i];
    }
}