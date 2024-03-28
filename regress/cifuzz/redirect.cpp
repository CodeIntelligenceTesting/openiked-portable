#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

void read()
{
    std::istream in("dump.json", std::fstream::in);

    nlohmann::json args;
    in >> args;

    int    argsc = args.size();
    char **argsv = new char* [argsc+1];
    for(int i=0; i<args.size(); ++i) {
        std::string arg = args.at(i);
        argsv[i] = new char[arg.size() + 1];
        strcpy(argsv[i], arg.c_str());
    }
    argsv[argsc] = nullptr;

    for(int i=0; i<argsc; ++i) {
        printf("%d: %s\n", i, argsv[i]);
    }
}

void write(int argsc, char **argsv)
{
    nlohmann::json args = nlohmann::json::array();
    for (int i=0; i!=argsc; ++i) {
        args.push_back(std::string(argsv[i]));
    }

    std::fstream out("dump.json", std::fstream::out | std::fstream::trunc);
    // serialize JSON
    out << std::setw(2) << args << '\n';
}

int main(int argsc, char **argsv)
{
    write(argsc, argsv);
    read();
}