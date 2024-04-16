#include <unistd.h>

#include <event.h>

#include "cifuzz_vroute_cleanup_leaked_sockets.h"

/*
 * structure definitions copy-pasted from
 * https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/vroute-netlink.c#L61
 */
struct vroute_addr {
	int				va_ifidx;
	struct	sockaddr_storage	va_addr;
	struct	sockaddr_storage	va_mask;
	TAILQ_ENTRY(vroute_addr)	va_entry;
};
TAILQ_HEAD(vroute_addrs, vroute_addr);

struct vroute_route {
	struct	sockaddr_storage	vr_dest;
	TAILQ_ENTRY(vroute_route)	vr_entry;
};
TAILQ_HEAD(vroute_routes, vroute_route);

struct vroute_dns {
	struct	sockaddr_storage	vd_addr;
	int				vd_ifidx;
	TAILQ_ENTRY(vroute_dns)		vd_entry;
};
TAILQ_HEAD(vroute_dnss, vroute_dns);

struct iked_vroute_sc {
	struct vroute_addrs	 ivr_addrs;
	struct vroute_dnss	 ivr_dnss;
	struct vroute_routes	 ivr_routes;
	int			 ivr_rtsock;
#ifdef WITH_SYSTEMD
	sd_bus			*ivr_bus;
#endif
};

void cifuzz_vroute_cleanup_leaked_sockets(struct iked *env) {
  struct iked_vroute_sc *ivr = env->sc_vroute;
  
  /*
   * leaked after allocation in
   * https://github.com/openiked/openiked-portable/blob/a0fc2e0d629a081b170adabc8d092653b07f1d4a/iked/vroute-netlink.c#L108
   */
  if (ivr->ivr_rtsock >= 0) {
    close(ivr->ivr_rtsock);
    ivr->ivr_rtsock = -1;
  }
}
