#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/un.h>
#include <sys/tree.h>

#include <errno.h>
#include <unistd.h>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <string>

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
    int  connectHelper(const char *sock, struct parse_result *res);
    void reconnectHelper(const char *sock, struct parse_result *res, int ctl_sock, struct sockaddr_un &s_un);
};

IkedControlFuzzer::IkedControlFuzzer()
    : res(parse(0, NULL))
    , ctl_sock(connectHelper(IKED_SOCKET, res))
{
}

/*
 * stub
 */
struct parse_result *IkedControlFuzzer::parse(int argsc, char **argsv)
{
    (void)argsc;
    (void)argsv;

    memset(&m_res_storage, 0, sizeof(m_res_storage));
    
    return &m_res_storage;
}

void IkedControlFuzzer::err(int exit_code, const char *fmt, ...)
{
    char *freeMe(nullptr);
    va_list args;
    va_start (args, fmt);
    vasprintf(&freeMe, fmt, args);
    va_end (args);

    std::string diagnostic(freeMe);
    free(freeMe);

    throw std::runtime_error(diagnostic);
}

/*
 * From https://github.com/openiked/openiked-portable/blob/6d5b015f50301ffb1800f36f636b953a714c9e62/ikectl/ikectl.c#L227
 */
int IkedControlFuzzer::connectHelper(const char *sock, struct parse_result *res)
{
    struct sockaddr_un s_un;
    int ctl_sock;

    if ((ctl_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		err(1, "socket");

	bzero(&s_un, sizeof(s_un));
	s_un.sun_family = AF_UNIX;
	strlcpy(s_un.sun_path, sock, sizeof(s_un.sun_path));

    reconnectHelper(sock, res, ctl_sock, s_un);
}

/*
 * From https://github.com/openiked/openiked-portable/blob/6d5b015f50301ffb1800f36f636b953a714c9e62/ikectl/ikectl.c#L235
 */
void IkedControlFuzzer::reconnectHelper(const char *sock, struct parse_result *res,  int ctl_sock, struct sockaddr_un &s_un)
{
    if (connect(ctl_sock, (struct sockaddr *)&s_un, sizeof(s_un)) == -1) {
		/* Keep retrying if running in monitor mode */
		if ( res->action == MONITOR &&
		    (errno == ENOENT || errno == ECONNREFUSED)) {
			usleep(100);
			reconnectHelper(sock, res, ctl_sock, s_un);
		}
		err(1, "connect: %s", sock);
	}
}