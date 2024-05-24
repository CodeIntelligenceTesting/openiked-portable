#ifndef TIMER_MOCKS_H
#define TIMER_MOCKS_H

#include "iked.h"

const int MAX_EVENT_RECURSION_DEPTH = 10;

/*
Here we want to immediately call the callback function
in blocking mode.
Recursion depth is introduced to limit recursive event_add calls
*/
int __wrap_event_add(struct event *ev, const struct timeval *timeout) {
#ifdef DEBUG
    printf("Called mocked event_add.\n")
#endif

        static int current_recursion_depth = 0;

    if (ev && ev->ev_evcallback.evcb_cb_union.evcb_callback) {
        if (current_recursion_depth < MAX_EVENT_RECURSION_DEPTH) {
            current_recursion_depth++;
            ev->ev_evcallback.evcb_cb_union.evcb_callback(
                ev->ev_fd, ev->ev_events, ev->ev_evcallback.evcb_arg);
            current_recursion_depth--;

        } else {
            return -1;
        }
    }

    return 0;
}

#endif