#include "ca.h"

void
ca_init(struct iked	*env)
{
	struct ca_store	*store;

	if ((store = calloc(1, sizeof(*store))) == NULL)
		fatal("%s: failed to allocate cert store", __func__);

	env->sc_priv = store;
}