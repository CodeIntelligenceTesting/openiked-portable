#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main(int argsc, char **argsv)
{
    // create stream with serialized JSON
    std::stringstream ss;
    
    nlohmann::json args = nlohmann::json::array();
    for (int i=0; i!=argsc; ++i) {
        args.push_back(std::string(argsv[i]));
    }

    std::fstream out("dump.json", std::fstream::out | std::fstream::trunc);
    // serialize JSON
    out << std::setw(2) << args << '\n';
}