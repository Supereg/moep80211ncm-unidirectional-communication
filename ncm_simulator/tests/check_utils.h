//
// Created by Andreas Bauer on 19.03.21.
//

#ifndef MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_CHECK_UTILS_H
#define MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_CHECK_UTILS_H

#include <check.h>

#include "check_simulator.h"

#include "../src/session.h"

struct check_test_context;
typedef struct check_test_context check_test_context_t;

/**
 * Use to store a call to the `os_callback` in order to make it available to the test case.
 */
typedef struct os_frame_entry {
    struct list_head list;
    int index;

    session_t* session;
    u16 ether_type;
    u8 payload[CHECK_MAX_PDU];
    size_t length;
} os_frame_entry_t;

// TODO bunch docs missing

/**
 * This method initializes the global `check_context`.
 * What is does is, it sets up a signal handler for the real-time signal SIGRTMIN
 * which is used by our timeout.h to signal timeout expiration.
 * We block the signal and create a file descriptor to read from it later.
 * This basically queues all timer expirations,
 * as otherwise the process would just exit (as it is the default for real-time signals).
 *
 * `close_check_utils` must be called to free all data and close file descriptors.
 */
void init_check_utils();
/**
 * Closes all file descriptors opened in `init_check_utils`.
 */
void close_check_utils();

check_test_context_t* test_init(
    session_t* source,
    session_t* intermediate,
    session_t* destination,
    double forwarding_probability,
    int forwarding_timeout);

void test_free(check_test_context_t* context);

int check_rtx_frame_callback(session_subsystem_context_t* session_context, session_t* session, coded_packet_metadata_t* metadata, u8* payload, size_t length);
int check_os_frame_callback(session_subsystem_context_t* context, session_t* session, u16 ether_type, u8* payload, size_t length);

void await(int ms);
void await_os_frame();

os_frame_entry_t * pop_os_frame_entry(); // Don't forget to free(...) after pop
os_frame_entry_t * peek_os_frame_entry(int index);

#endif //MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_CHECK_UTILS_H
