//
// Created by Andreas Bauer on 19.03.21.
//

#ifndef CHECK_UTILS_H
#define CHECK_UTILS_H

#include <check.h>

#include "check_suites.h"

#include "../src/session.h"

struct check_test_context;
typedef struct check_test_context check_test_context_t;

/**
 * Use to store a call to the `os_callback` in order
 * to make it available to the test case.
 */
struct os_frame_entry {
	struct list_head list;
	int index;

	session_t* session;
	u16 ether_type;
	u8 payload[CHECK_MAX_PDU];
	size_t length;
};

/**
 * This method initializes the global `check_context`.
 * What is does is, it sets up a signal handler for the real-time
 * signal SIGRTMIN, which is used by our timeout.h to signal timeout expiration.
 * We block the signal and create a file descriptor to read from it later.
 * This basically queues all timer expirations, as otherwise the process
 * would just exit (as it is the default for real-time signals).
 *
 * `close_check_utils` must be called to free all data
 * and close file descriptors.
 */
void
init_check_utils();
/**
 * Closes all file descriptors opened in `init_check_utils`.
 */
void
close_check_utils();

/**
 * Initializes a new `check_test_context_t`.
 * This function is used to define any test specific configuration
 * use within `check_rtx_frame_callback`, `await_fully_decoded` or other.
 *
 * @param source - The session which is considered the SOURCE node.
 * @param intermediate - The session which is considered the INTERMEDIATE node.
 * 	Pass NULL to disable forwarding node.
 * 	NOTE: Forwarders are currently unsupported!
 * @param destination - The session which is considered the DESTINATION node.
 * @param forwarding_probability - A value in the interval [0;1] defining
 * 	the link quality between nodes.
 * 	This is used to simulate random packet loss.
 * @param max_forwarding_timeout - If set to a value bigger than zero,
 * 	for each forwarded frame, a random value will be drawn between zero
 * 	and the given number. The frame will be delayed for the drawn
 * 	delay (in milliseconds). This is to simulate any delay in transmission.
 * @return The created `check_test_context_t` which is to be freed
 * 	using `test_free` once the test is completed.
 */
check_test_context_t*
test_init(session_t* source,
	session_t* intermediate,
	session_t* destination,
	double forwarding_probability,
	s64 max_forwarding_timeout);

/**
 * Returns if a `check_test_context_t` is currently initialized.
 */
bool
test_initialized();

/**
 * Closes the given `check_test_context_t` and frees its memory.
 * @param context - `check_test_context_t` to be freed.
 */
void
test_free(check_test_context_t* context);

/**
 * This is a default `encoded_payload_callback` for the `rtx_callback`
 * of the `session_subsystem_context`.
 * It must be set manually on the `init_session_subsystem` call.
 * The callback will forward received coded frames to the
 * appropriate session configured in the current `check_test_context_t`.
 * Depending of the configurations set in `check_test_context_t`
 * it will randomly drop frames or impose a random forwarding timeout
 * (The forwarding timeout require the run_loop to be executed).
 *
 * Note: This callback handler requires a `check_test_context_t` to
 * be initialized via `test_init`.
 */
int
check_rtx_frame_callback(struct session_subsystem_context* session_context,
	session_t* session,
	struct coded_packet_metadata* metadata,
	u8* payload,
	size_t length);
/**
 * This is a default `decoded_payload_callback` for the `os_callback`
 * of the `session_subsystem_context`.
 * It must be set manually on the `init_session_subsystem` call.
 * This callback makes all decoded frames available to the unit tests,
 * by saving those in a linked list of `struct os_frame_entry`.
 *
 * The list can be read using `os_frame_entries_emtpy`,
 * `pop_os_frame_entry` and `peek_os_frame_entry`.
 */
int
check_os_frame_callback(struct session_subsystem_context* context,
	session_t* session,
	u16 ether_type,
	u8* payload,
	size_t length);


/**
 * This function runs the `run_loop` (blocking) for the specified amount of time.
 *
 * The `run_loop` is used to execute any timers (created via timeout.h)
 * which signals are currently queued (or are about to be queued in
 * the given time frame).
 * In order to run the `run_loop`, `init_check_utils` has to be called
 * first to create all necessary file descriptors.
 *
 * @param ms - The execution time in milliseconds.
 */
void
await(int ms);

/**
 * This function runs the `run_loop` (blocking) until the DESTINATION session
 * is able to decode all frames added to the SOURCE session AND
 * the SOURCE session did receive an ACK for all those frames.
 *
 * See `await(int ms)` for an explanation on the `run_loop` and its requirements.
 * This function requires that a test context has been set up via `test_init`.
 */
void
await_fully_decoded();


/**
 * @return Returns if the the `os_frame_entries` list
 * 	(the list holding all received decoded frames as `struct os_frame_entry`)
 * 	is empty.
 */
bool
os_frame_entries_emtpy();

/**
 * Pops the first entry of the `os_frame_entries` list.
 * @return Returns a pointer to the popped `os_frame_entry`.
 * NOTE!: The check_utils won't keep a reference to that frame.
 * 	It is your responsibility to call `free(...)` for the popped frame
 * 	if the memory isn't needed anymore!
 */
struct os_frame_entry*
pop_os_frame_entry();

/**
 * Reads a `os_frame_entry` from the `os_frame_entries` list at given index.
 * @param index - Index to read a element from.
 * 	If the index is out of bounds, the program will abort by making
 * 	a call to `ck_abort_msg`.
 * @return Returns a pointer to the `os_frame_entry` at the given position.
 */
struct os_frame_entry*
peek_os_frame_entry(int index);

#endif //CHECK_UTILS_H
