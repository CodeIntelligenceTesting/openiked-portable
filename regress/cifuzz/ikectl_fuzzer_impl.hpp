#pragma once

#include "../../ikectl/parser.h"
#include "../../iked/types.h"

struct IkedControlFuzzer
{
    IkedControlFuzzer();
    ~IkedControlFuzzer();

protected:
    struct parse_result	*res;
    int ctl_sock;

protected:
    struct parse_result	m_res_storage;
    struct parse_result *parse(int argsc, char **argsv);

    void err(int exit_code, const char *fmt, ...);
    void connectHelper(const char *sock, struct parse_result *res);
    void reconnectHelper(const char *sock, struct sockaddr_un &s_un);
};
