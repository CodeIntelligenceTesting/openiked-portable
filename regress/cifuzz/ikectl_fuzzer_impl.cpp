#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/un.h>
#include <sys/tree.h>

#include <unistd.h>

#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <stdexcept>

#include "../../ikectl/parser.h"
#include "../../iked/types.h"

struct IkedControlFuzzer
{
    IkedControlFuzzer();
    ~IkedControlFuzzer();

    static void err(int exit_code, const char *fmt, ...);
    static int  connectHelper(const char *sock, struct parse_result *res);
    static void reconnectHelper(const char *sock, struct parse_result *res, int ctl_sock, struct sockaddr_un &s_un);

protected:
    struct parse_result	*res;
    int ctl_sock;

protected:
    struct parse_result	m_res_storage;
    static struct parse_result *parse(int argsc, char **argsv);
};

IkedControlFuzzer::IkedControlFuzzer()
    : res(parse(0, NULL))
    , ctl_sock(connectHelper())
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
			reconnectHelper(ctl_sock, s_un);
		}
		err(1, "connect: %s", sock);
	}
}